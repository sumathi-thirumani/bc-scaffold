"""Run npm-check-updates against an isolated manifest and collect candidates."""
import asyncio
import json
import logging
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from ...models.remediation_plan import RemediationPlan, RemediationReconcileInfo
from ...tools.ecosystem_manifest_tool import ManifestTool
from ...utils.subprocess_env import minimal_subprocess_env

logger = logging.getLogger(__name__)
MAX_LOGGED_OUTPUT_CHARS = 2000

NPM_ECOSYSTEMS = frozenset({"npm", "npm_and_yarn", "yarn"})
NCU_REJECTED_PACKAGES = frozenset({"bootstrap", "typescript"})
SEMVER_PATTERN = re.compile(r"(?<!\d)v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)")

NCU_VERSION = "23.1.0"
NPM_DEPENDENCY_FIELDS = (
    "dependencies", "devDependencies", "optionalDependencies", "peerDependencies",
)

@dataclass
class NpmCheckUpdatesResult:
    process: subprocess.CompletedProcess[str]
    upgrades: dict[str, str]
    declared_versions: dict[str, str]


class NpmCompatibleVersionReviewer:
    def __init__(self, manifest_tool: ManifestTool) -> None:
        self.manifest_tool = manifest_tool

    async def review(self, remediation_plan: RemediationPlan, repo: dict[str, str], *,
                     ref: str | None = None) -> RemediationPlan:
        npm_manifest_paths: set[str] = set()
        for bundle in remediation_plan.remediation_plan_bundles:
            logger.info("Processing bundle %s", bundle.groupName)
            for package in bundle.packages:
                if package.ecosystem.lower() not in NPM_ECOSYSTEMS:
                    continue
                if package.manifest_path:
                    npm_manifest_paths.add(self._package_json_path(package.manifest_path))
        owner = repo.get("owner")
        repository = repo.get("repo") or repo.get("name")
        if npm_manifest_paths and (not owner or not repository):
            raise ValueError("Repository owner and name are required for npm review")
        reconciliation_notes: list[str] = []
        for manifest_path in sorted(npm_manifest_paths):
            package_text = await self.manifest_tool.get(
                owner,
                repository,
                manifest_path,
                ref,
            )
            if package_text is None:
                logger.warning(
                    "Skipping npm-check-updates: cannot fetch %s from %s/%s",
                    manifest_path,
                    owner,
                    repository,
                )
                continue
            package_names = {
                recommendation.package
                for bundle in remediation_plan.remediation_plan_bundles
                for triage in bundle.packages
                if triage.ecosystem.lower() in NPM_ECOSYSTEMS and triage.manifest_path
                and self._package_json_path(triage.manifest_path) == manifest_path
                for recommendation in triage.package_upgrade_recommendations
            }
            if not package_names:
                continue
            ncu_result = await asyncio.to_thread(
                NpmCompatibleVersionReviewer._run_npm_check_updates,
                package_text, package_names,
            )
            result = ncu_result.process
            output = "\n".join(
                part.strip() for part in (result.stdout, result.stderr) if part.strip()
            )
            log = logger.info if result.returncode == 0 else logger.error
            log(
                "npm-check-updates for %s exited with code %d%s",
                manifest_path,
                result.returncode,
                f" (output truncated):\n{self._truncate_output(output)}"
                if output and result.returncode != 0
                else "",
            )
            reconciliation_notes.append(
                f"Manifest: {manifest_path}\n"
                f"Exit code: {result.returncode}\n"
                f"{output or '(no output)'}"
            )
            if result.returncode == 0:
                self._populate_minimum_upgradable_versions(
                    remediation_plan,
                    ncu_result.upgrades,
                    ncu_result.declared_versions,
                    manifest_path,
                )
        for note in reconciliation_notes:
            logger.info("npm reconciliation: %s", note)
        return remediation_plan

    @staticmethod
    def _truncate_output(output: str, limit: int = MAX_LOGGED_OUTPUT_CHARS) -> str:
        if len(output) <= limit:
            return output
        return f"{output[:limit]}... [{len(output) - limit} more characters]"


    @staticmethod
    def _run_npm_check_updates(
        package_text: str,
        package_names: set[str] | None = None,
    ) -> NpmCheckUpdatesResult:
        npx = shutil.which("npx") or shutil.which("npx.cmd")
        if npx is None:
            raise RuntimeError("npx is required for npm package review")
        with tempfile.TemporaryDirectory(prefix="npm_check_updates_") as tmp:
            package_path = Path(tmp, "package.json")
            package_path.write_text(package_text, encoding="utf-8")
            result = subprocess.run(
                [
                    npx,
                    "--yes",
                    f"npm-check-updates@{NCU_VERSION}",
                    "--target",
                    "latest",
                    "--peer",
                    "--enginesNode",
                    "--reject",
                    "bootstrap,typescript",
                    "-u",
                    *(["--filter", ",".join(sorted(package_names))] if package_names else []),
                ],
                cwd=tmp,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=300,
                env=minimal_subprocess_env({"NO_COLOR": "1"}),
            )
            updated_package_text = package_path.read_text(encoding="utf-8")
            return NpmCheckUpdatesResult(
                process=result,
                upgrades=NpmCompatibleVersionReviewer._updated_dependencies(
                    package_text,
                    updated_package_text,
                ),
                declared_versions=NpmCompatibleVersionReviewer._declared_dependencies(
                    package_text,
                ),
            )
    @staticmethod
    def _declared_dependencies(package_text: str) -> dict[str, str]:
        package = json.loads(package_text)
        return {
            name.casefold(): version
            for field in NPM_DEPENDENCY_FIELDS
            for name, version in (package.get(field) or {}).items()
            if isinstance(version, str)
        }
    @staticmethod
    def _updated_dependencies(
        original_package_text: str,
        updated_package_text: str,
    ) -> dict[str, str]:
        original = json.loads(original_package_text)
        updated = json.loads(updated_package_text)
        upgrades: dict[str, str] = {}
        for field in NPM_DEPENDENCY_FIELDS:
            original_dependencies = original.get(field) or {}
            for package, target in (updated.get(field) or {}).items():
                if target != original_dependencies.get(package):
                    upgrades[package.casefold()] = target
        return upgrades
    @staticmethod
    def _package_json_path(manifest_path: str) -> str:
        path = PurePosixPath(manifest_path)
        if path.name == "package.json":
            return str(path)
        return str(path.parent / "package.json")
    @staticmethod
    def _populate_minimum_upgradable_versions(
        remediation_plan: RemediationPlan,
        upgrades: dict[str, str],
        declared_versions: dict[str, str],
        manifest_path: str,
    ) -> None:
        for bundle in remediation_plan.remediation_plan_bundles:
            for triage in bundle.packages:
                if triage.ecosystem.lower() not in NPM_ECOSYSTEMS or not triage.manifest_path:
                    continue
                if NpmCompatibleVersionReviewer._package_json_path(triage.manifest_path) != manifest_path:
                    continue
                for recommendation in triage.package_upgrade_recommendations:
                    name = recommendation.package.casefold()
                    target = declared_versions.get(name) if name in NCU_REJECTED_PACKAGES else upgrades.get(name)
                    match = SEMVER_PATTERN.search(target or "")
                    if match:
                        recommendation.compatible_version = match.group(1)
