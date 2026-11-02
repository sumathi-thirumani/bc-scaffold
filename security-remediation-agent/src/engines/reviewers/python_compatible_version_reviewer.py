"""Collect pip/Python candidates with pur, uv-upsync or Poetry in dry-run mode."""
import asyncio
import json
import logging
import re
import shutil
import subprocess
import tempfile
from pathlib import Path, PurePosixPath

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from ...models.remediation_plan import RemediationPlan, RemediationReconcileInfo
from ...utils.subprocess_env import minimal_subprocess_env

try:
    import tomllib
except ImportError:
    import tomli as tomllib

logger = logging.getLogger(__name__)

PYTHON_ECOSYSTEMS = frozenset({"pip", "pypi", "python", "poetry"})


class PythonCompatibleVersionReviewer:
    def __init__(self, manifest_tool):
        self.manifest_tool = manifest_tool

    @staticmethod
    def _pinned_requirements(text, packages):
        selected = {}
        for line in text.splitlines():
            try:
                requirement = Requirement(line.split(" #", 1)[0].strip())
            except InvalidRequirement:
                continue
            name = canonicalize_name(requirement.name)
            specs = list(requirement.specifier)
            if name not in packages or requirement.url or len(specs) != 1:
                continue
            spec = specs[0]
            if spec.operator != "==":
                continue
            try:
                Version(spec.version)
            except InvalidVersion:
                continue
            if name in selected and selected[name] != spec.version:
                raise ValueError(f"Multiple pinned versions for {name}")
            selected[name] = spec.version
        return selected

    @classmethod
    def _run_pur(cls, text, packages):
        declared = cls._pinned_requirements(text, packages)
        if not declared:
            return {}
        executable = shutil.which("pur") or shutil.which("pur.exe")
        if executable is None:
            raise RuntimeError("pur is required for Python compatible version review")
        names = ",".join(sorted(declared))
        with tempfile.TemporaryDirectory(prefix="pur_review_") as tmp:
            # Only selected literal pins are passed; repository includes and index directives
            # must not cause local file reads or change registry configuration.
            Path(tmp, "requirements.in").write_text(
                "".join(f"{name}=={version}\n" for name, version in declared.items()),
                encoding="utf-8",
            )
            result = subprocess.run(
                [executable, "-r", "requirements.in", "--dry-run-changed",
                 "--minor", names, "--only", names, "--no-recursive"],
                cwd=tmp, capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=300, env=minimal_subprocess_env({"NO_COLOR": "1"}),
            )
        if result.returncode:
            raise RuntimeError(f"pur exited with code {result.returncode}")
        candidates = cls._pinned_requirements(result.stdout, declared)
        return {
            name: version for name, version in candidates.items()
            if Version(version) > Version(declared[name])
            and Version(version).major == Version(declared[name]).major
            and not Version(version).is_prerelease and not Version(version).is_devrelease
        }

    @staticmethod
    def _run_uv_upsync(text, packages):
        executable = shutil.which("uvx") or shutil.which("uvx.exe")
        if executable is None:
            raise RuntimeError("uvx is required for uv compatible version review")
        args = [executable, "uv-upsync", "--max-bump", "minor", "--dry-run",
                "--format", "json", "--all-groups", "--color", "never"]
        for name in sorted(packages):
            args.extend(["--upgrade-package", name])
        with tempfile.TemporaryDirectory(prefix="uv_upsync_review_") as tmp:
            Path(tmp, "pyproject.toml").write_text(text, encoding="utf-8")
            result = subprocess.run(
                args, cwd=tmp, capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=300,
                env=minimal_subprocess_env({"NO_COLOR": "1"}),
            )
        if result.returncode:
            raise RuntimeError(f"uv-upsync exited with code {result.returncode}")
        try:
            payload = json.loads(result.stdout)
            updates = payload["updated"]
            if not isinstance(updates, list):
                raise ValueError("Expected an updated list")
            candidates = {}
            for update in updates:
                name = canonicalize_name(update["name"])
                old, new = Version(update["old"]), Version(update["new"])
                if name not in packages or new <= old or new.major != old.major:
                    continue
                if new.is_prerelease or new.is_devrelease:
                    continue
                previous = candidates.get(name)
                if previous is not None and Version(previous) != new:
                    raise ValueError(f"Conflicting uv candidates for {name}")
                candidates[name] = update["new"]
            return candidates
        except (KeyError, TypeError, AttributeError) as exc:
            raise ValueError("Invalid uv-upsync JSON report") from exc

    @staticmethod
    def _poetry_versions(data, packages):
        versions = {}
        poetry = data.get("tool", {}).get("poetry", {})
        sections = [poetry.get("dependencies", {}), poetry.get("dev-dependencies", {})]
        sections.extend(group.get("dependencies", {}) for group in poetry.get("group", {}).values())
        for section in sections:
            for raw_name, value in section.items():
                name = canonicalize_name(raw_name)
                if name not in packages:
                    continue
                constraint = value.get("version", "") if isinstance(value, dict) else value
                # Poetry up emits a caret, tilde or >= constraint with its selected version.
                match = re.fullmatch(r"(?:\^|~=|~|>=|==)?\s*(\d+(?:\.\d+)*(?:[a-zA-Z0-9.+-]*))", constraint)
                if match:
                    versions.setdefault(name, set()).add(match.group(1))
        project = data.get("project", {})
        requirements = list(project.get("dependencies", []))
        for group in project.get("optional-dependencies", {}).values():
            requirements.extend(group)
        for raw in requirements:
            requirement = Requirement(raw)
            name = canonicalize_name(requirement.name)
            specs = list(requirement.specifier)
            if name in packages and len(specs) == 1 and specs[0].operator in {">=", "==", "~="}:
                versions.setdefault(name, set()).add(specs[0].version)
        # Different constraints for one package cannot be represented by one candidate.
        return {name: next(iter(values)) for name, values in versions.items() if len(values) == 1}

    @classmethod
    def _run_poetry_up(cls, text, packages):
        executable = shutil.which("poetry") or shutil.which("poetry.exe")
        if executable is None:
            raise RuntimeError("Poetry is required; install poetry-plugin-up with poetry self add poetry-plugin-up")
        original = cls._poetry_versions(tomllib.loads(text), packages)
        with tempfile.TemporaryDirectory(prefix="poetry_up_review_") as tmp:
            Path(tmp, "pyproject.toml").write_text(text, encoding="utf-8")
            result = subprocess.run(
                [executable, "up", "--dry-run", "--no-ansi", "--no-interaction", "--", *sorted(packages)],
                cwd=tmp, capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=300,
                env=minimal_subprocess_env({"NO_COLOR": "1"}),
            )
        if result.returncode:
            raise RuntimeError(f"poetry up exited with code {result.returncode}; "
                               "ensure poetry self add poetry-plugin-up has been run")
        # The plugin can print 'No new version' notices before the TOML document.
        output = result.stdout
        lines = output.splitlines()
        while lines and lines[0].startswith("No new version for "):
            lines.pop(0)
        updated = cls._poetry_versions(tomllib.loads("\n".join(lines)), packages)
        return {name: version for name, version in updated.items()
                if name in original and Version(version) > Version(original[name])
                and Version(version).major == Version(original[name]).major
                and not Version(version).is_prerelease and not Version(version).is_devrelease}

    async def review(self, plan: RemediationPlan, repo: dict[str, str], *, ref=None):
        by_manifest = {}
        notes = []
        for bundle in plan.remediation_plan_bundles:
            for package in bundle.packages:
                if package.ecosystem.lower() not in PYTHON_ECOSYSTEMS:
                    continue
                triage = package
                if not triage.manifest_path:
                    continue
                manifest = PurePosixPath(triage.manifest_path.replace("\\", "/"))
                if manifest.name in {"pyproject.toml", "uv.lock", "poetry.lock"}:
                    path = manifest.with_name("pyproject.toml").as_posix()
                else:
                    path = self.manifest_tool.declaration_path(package.ecosystem, triage.manifest_path)
                if path and (PurePosixPath(path).suffix in {".in", ".txt"}
                             or PurePosixPath(path).name == "pyproject.toml"):
                    by_manifest.setdefault(path, []).extend(
                            (recommendation, triage) for recommendation in triage.package_upgrade_recommendations
                        )
                else:
                    notes.append(f"{triage.manifest_path}: unsupported requirements format")
        owner = repo.get("owner")
        repository = repo.get("repo") or repo.get("name")
        if by_manifest and (not owner or not repository):
            raise ValueError("Repository owner and name are required for Python review")
        for path, entries in sorted(by_manifest.items()):
            try:
                text = await self.manifest_tool.get(owner, repository, path, ref)
                if text is None:
                    raise ValueError(f"Cannot fetch {path}")
                names = {canonicalize_name(package.package) for package, _ in entries}
                is_uv = PurePosixPath(path).name == "pyproject.toml"
                is_poetry = is_uv and (
                    any(triage.ecosystem.lower() == "poetry"
                        or PurePosixPath(triage.manifest_path).name == "poetry.lock"
                        for package, triage in entries)
                    or "poetry" in tomllib.loads(text).get("tool", {})
                )
                runner = self._run_poetry_up if is_poetry else (
                    self._run_uv_upsync if is_uv else self._run_pur
                )
                candidates = await asyncio.to_thread(runner, text, names)
                for package, triage in entries:
                    name = canonicalize_name(package.package)
                    candidate = candidates.get(name)
                    if not candidate:
                        continue
                    package.compatible_version = candidate
                tool_name = "poetry up" if is_poetry else ("uv-upsync" if is_uv else "pur")
                notes.append(f"{path}: {len(candidates)} {tool_name} same-major candidate(s); "
                             "not security-verified or install-tested")
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
                notes.append(f"{path}: FAILED: {exc}")
        for note in notes:
            logger.info("Python reconciliation: %s", note)
        return plan
