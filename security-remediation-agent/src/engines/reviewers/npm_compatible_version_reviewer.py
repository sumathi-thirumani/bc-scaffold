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

from ...models.remediation_plan import RemediationPlan
from ...models.security_package_triage import PackageUpgradeRecommendation
from ...tools.ecosystem_manifest_tool import ManifestTool
from ...utils.subprocess_env import minimal_subprocess_env
from .update_triage import add_update_triage

logger = logging.getLogger(__name__)
MAX_LOGGED_OUTPUT_CHARS = 2000

NPM_ECOSYSTEMS = frozenset({"npm", "npm_and_yarn", "yarn"})
#NCU_REJECTED_PACKAGES = frozenset({"bootstrap", "typescript"})   # Packages that npm-check-updates should ignore
NCU_REJECTED_PACKAGES = frozenset({})   # Packages that npm-check-updates should ignore
# Accepts only a single version with an optional ^, ~, >= or = prefix. Anything else
# (comparator sets, "||", aliases, workspace:, git or URL specs) is not trusted.
SINGLE_VERSION_PATTERN = re.compile(
    r"\s*(?:\^|~|>=|=)?\s*v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)(?:\+[0-9A-Za-z.-]+)?\s*"
)

UPGRADE_FOUND = "upgrade_found"
NO_UPGRADE = "no_upgrade"
EXCLUDED = "excluded"
NOT_DECLARED = "not_declared"
REVIEW_FAILED = "review_failed"

NCU_VERSION = "23.1.0"
NPM_DEPENDENCY_FIELDS = (
    "dependencies", "devDependencies", "optionalDependencies", "peerDependencies",
)

@dataclass
class NpmCheckUpdatesResult:
    """Keep tool diagnostics, proposed versions and original npm declarations together."""
    process: subprocess.CompletedProcess[str]
    upgrades: dict[str, str]
    declared_versions: dict[str, str]


class NpmCompatibleVersionReviewer:
    """Collect npm compatibility candidates with isolated npm-check-updates runs.

    Core idea: review each package.json once, map results to recommendations, and
    record per-package review outcomes. Optional additional updates enter triage
    before planning. Tool success does not imply npm resolution success."""
    def __init__(self, manifest_tool: ManifestTool, additional_updates: bool = False) -> None:
        self.manifest_tool = manifest_tool
        self.additional_updates = additional_updates

    async def review(self, remediation_plan: RemediationPlan, repo: dict[str, str], *,
                     ref: str | None = None) -> RemediationPlan:
        """Review each npm manifest once and attach candidates and per-package review outcomes."""
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
            recommendations = self._recommendations_for(remediation_plan, manifest_path)
            if not recommendations:
                continue
            try:
                package_text = await self.manifest_tool.get(
                    owner,
                    repository,
                    manifest_path,
                    ref,
                )
                if package_text is None:
                    raise ValueError(f"cannot fetch {manifest_path} from {owner}/{repository}")
                ncu_result = await asyncio.to_thread(
                    NpmCompatibleVersionReviewer._run_npm_check_updates,
                    package_text,
                    None if self.additional_updates else {r.package for r in recommendations},
                )
            except (subprocess.SubprocessError, OSError, RuntimeError, ValueError) as exc:
                logger.warning("npm-check-updates review failed for %s: %s", manifest_path, exc)
                self._mark(recommendations, REVIEW_FAILED)
                continue
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
                f"{self._truncate_output(output) if output else '(no output)'}"
            )
            if result.returncode == 0:
                self._populate_compatible_versions(
                    recommendations,
                    ncu_result.upgrades,
                    ncu_result.declared_versions,
                )
                if self.additional_updates:
                    self._add_update_triages(
                        remediation_plan, manifest_path, recommendations,
                        ncu_result.upgrades, ncu_result.declared_versions,
                    )
            else:
                self._mark(recommendations, REVIEW_FAILED)
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
                    ",".join(sorted(NCU_REJECTED_PACKAGES)),
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
    def _recommendations_for(
        remediation_plan: RemediationPlan, manifest_path: str
    ) -> list[PackageUpgradeRecommendation]:
        return [
            recommendation
            for bundle in remediation_plan.remediation_plan_bundles
            for triage in bundle.packages
            if triage.ecosystem.lower() in NPM_ECOSYSTEMS and triage.manifest_path
            and NpmCompatibleVersionReviewer._package_json_path(triage.manifest_path) == manifest_path
            for recommendation in triage.package_upgrade_recommendations
        ]

    @staticmethod
    def _add_update_triages(
        remediation_plan: RemediationPlan,
        manifest_path: str,
        recommendations: list[PackageUpgradeRecommendation],
        upgrades: dict[str, str],
        declared_versions: dict[str, str],
    ) -> None:
        """Add non-vulnerable packages that npm-check-updates would update to the "update" bundle."""
        vulnerable = {recommendation.package.casefold() for recommendation in recommendations}
        for name, target in sorted(upgrades.items()):
            current = NpmCompatibleVersionReviewer._single_version(declared_versions.get(name, ""))
            version = NpmCompatibleVersionReviewer._single_version(target)
            if name in vulnerable or name in NCU_REJECTED_PACKAGES or not current or not version:
                continue
            add_update_triage(
                remediation_plan,
                lambda t: t.ecosystem.lower() in NPM_ECOSYSTEMS and bool(t.manifest_path)
                and NpmCompatibleVersionReviewer._package_json_path(t.manifest_path) == manifest_path,
                name, current, version,
            )

    @staticmethod
    def _mark(recommendations: list[PackageUpgradeRecommendation], status: str) -> None:
        for recommendation in recommendations:
            recommendation.compatible_review_status = status

    @staticmethod
    def _single_version(spec: str) -> str | None:
        """Return the version of a simple range such as ^1.2.3, or None if it isn't one."""
        match = SINGLE_VERSION_PATTERN.fullmatch(spec)
        return match.group(1) if match else None

    @staticmethod
    def _populate_compatible_versions(
        recommendations: list[PackageUpgradeRecommendation],
        upgrades: dict[str, str],
        declared_versions: dict[str, str],
    ) -> None:
        for recommendation in recommendations:
            name = recommendation.package.casefold()
            if name in NCU_REJECTED_PACKAGES:
                recommendation.compatible_review_status = EXCLUDED
            elif name not in upgrades:
                recommendation.compatible_review_status = (
                    NO_UPGRADE if name in declared_versions else NOT_DECLARED
                )
            else:
                version = NpmCompatibleVersionReviewer._single_version(upgrades[name])
                if version is None:
                    logger.warning(
                        "Cannot read a single version for %s from npm-check-updates range %r",
                        recommendation.package,
                        upgrades[name],
                    )
                    recommendation.compatible_review_status = REVIEW_FAILED
                else:
                    recommendation.compatible_version = version
                    recommendation.compatible_review_status = UPGRADE_FOUND
