"""Verify complete proposed upgrade sets through dependency resolution, without installs."""
import asyncio
import logging
import tempfile
import subprocess
from pathlib import Path, PurePosixPath

import httpx
from packaging.version import InvalidVersion, Version
from packaging.utils import canonicalize_name

from ..engines.remediation_verification.upgrade_verifier import UnsupportedVerification
from ..engines.remediation_verification.verification_engine_factory import VerificationEngineFactory
from ..tools.ecosystem_manifest_tool import ManifestTool


logger = logging.getLogger(__name__)


class RemediationVerificationAgent:
    def __init__(self, manifest_tool=None, engine_factory=None):
        self.manifest_tool = manifest_tool or ManifestTool()
        self.engine_factory = engine_factory or VerificationEngineFactory()

    @staticmethod
    def _candidate(recommendation):
        try:
            current = Version(recommendation.from_version)
            minimum = Version(recommendation.minimum_patched_version)
            highest = Version(recommendation.highest_stable_version)
            compatible = Version(recommendation.compatible_version)
        except (InvalidVersion, TypeError):
            return None, "unresolved"
        if minimum > highest:
            return None, "unresolved"
        if minimum.major != current.major:
            return None, "breaking_change_deferred"
        if compatible.is_prerelease or compatible.is_devrelease:
            return None, "breaking_change_deferred"
        # A latest-version preview can exceed the qualifying metadata set. Fall back
        # only to evidenced candidates below that compatibility ceiling, never guess.
        candidates = []
        for raw in recommendation.qualifying_upgrade_versions:
            try:
                version = Version(raw)
            except (InvalidVersion, TypeError):
                continue
            if (minimum <= version <= highest and version <= compatible and version > current
                    and version.major == current.major and not version.is_prerelease
                    and not version.is_devrelease):
                candidates.append((version, raw))
        if not candidates:
            return None, "unresolved"
        exact = next((raw for version, raw in candidates if version == compatible), None)
        return exact or min(candidates)[1], "requires_validation"

    async def _snapshot(self, root, repo, ref):
        owner = repo.get("owner")
        name = repo.get("repo") or repo.get("name")
        if not owner or not name:
            raise ValueError("Repository owner and name are required for verification")
        if ref is None:
            ref = await self.manifest_tool.resolve_ref(owner, name)
            if ref is None:
                raise ValueError("Cannot pin a repository snapshot for verification")
        entries = await self.manifest_tool.repository_tree(owner, name, ref)
        for entry in entries:
            path = PurePosixPath(entry["path"])
            if path.is_absolute() or ".." in path.parts or "\\" in str(path) or ":" in str(path):
                raise ValueError("Unsafe repository artifact path")
            if entry.get("type", "blob") != "blob":
                continue
            if path.name not in {"package.json", "package-lock.json", "pyproject.toml", "uv.lock",
                                 "poetry.lock", "uv.toml", ".python-version"} and path.suffix not in {".in", ".txt"}:
                continue
            text = await self.manifest_tool.get(owner, name, str(path), ref)
            if text is None:
                raise ValueError(f"Cannot fetch verification input: {path}")
            target = root.joinpath(*path.parts)
            if not target.resolve().is_relative_to(root.resolve()):
                raise ValueError("Verification path escapes the snapshot")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")

    @staticmethod
    def _mark(entries, status, notes):
        for _, recommendation, _ in entries:
            recommendation.verified_version = None
            recommendation.verification_status = status
            recommendation.verification_method = "dependency_resolution"
            recommendation.verification_notes = notes
            logger.info("Verification %s: %s (%s)", recommendation.package, status, notes)

    async def verify(self, remediation_plan, repo, *, ref=None):
        pending = []
        seen = set()
        for bundle in remediation_plan.remediation_plan_bundles:
            for triage in bundle.packages:
                for recommendation in triage.package_upgrade_recommendations:
                    if id(recommendation) in seen:
                        continue
                    seen.add(id(recommendation))
                    recommendation.verified_version = None
                    recommendation.verification_method = None
                    recommendation.verification_notes = ""
                    try:
                        candidate, status = self._candidate(recommendation)
                    except InvalidVersion:
                        candidate, status = None, "unresolved"
                    recommendation.verification_status = status
                    if candidate is None:
                        recommendation.verification_notes = (
                            f"No qualifying compatible non-breaking candidate: current={recommendation.from_version}, "
                            f"minimum={recommendation.minimum_patched_version}, highest={recommendation.highest_stable_version}, "
                            f"compatible={recommendation.compatible_version}"
                        )
                        logger.info("Verification %s: %s (%s)", recommendation.package, status,
                                    recommendation.verification_notes)
                        continue
                    pending.append((triage, recommendation, candidate))
        if not pending:
            return remediation_plan
        with tempfile.TemporaryDirectory(prefix="remediation_verification_") as tmp:
            snapshot = Path(tmp)
            try:
                await self._snapshot(snapshot, repo, ref)
            except (OSError, ValueError, httpx.HTTPError) as exc:
                self._mark(pending, "unresolved", str(exc))
                return remediation_plan
            groups = {}
            for entry in pending:
                triage, recommendation, candidate = entry
                try:
                    engine = self.engine_factory.create(triage.ecosystem)
                    if not triage.manifest_path:
                        raise UnsupportedVerification("Missing manifest path")
                    path = PurePosixPath(triage.manifest_path.replace("\\", "/"))
                    if path.is_absolute() or ".." in path.parts or ":" in str(path):
                        raise UnsupportedVerification("Unsafe manifest path")
                    manifest = engine.manifest(str(path))
                    if not (snapshot / manifest).is_file():
                        raise UnsupportedVerification(f"Missing declaration manifest: {manifest}")
                    project = engine.project_root(snapshot, manifest)
                    group = groups.setdefault((engine.family, project), (engine, [], {}))
                    group[1].append(entry)
                    targets = group[2].setdefault(manifest, {})
                    package_name = recommendation.package.casefold() if engine.family == "npm" else canonicalize_name(recommendation.package)
                    old = targets.get(package_name)
                    if package_name in targets and old != candidate:
                        # Do not resolve a set assembled from incompatible recommendations.
                        targets[package_name] = None
                    else:
                        targets[package_name] = candidate
                except (OSError, ValueError) as exc:
                    self._mark([entry], "unsupported", str(exc))
            for (_, project), (engine, entries, targets) in groups.items():
                if any(version is None for upgrades in targets.values() for version in upgrades.values()):
                    self._mark(entries, "unresolved", "Conflicting candidate versions within the upgrade set")
                    continue
                try:
                    await asyncio.to_thread(engine.verify, snapshot, project, targets)
                except UnsupportedVerification as exc:
                    self._mark(entries, "unsupported", str(exc))
                    continue
                except (OSError, ValueError, subprocess.SubprocessError) as exc:
                    self._mark(entries, "validation_failed", str(exc))
                    continue
                for _, recommendation, candidate in entries:
                    recommendation.verified_version = candidate
                    recommendation.verification_status = "resolution_verified"
                    recommendation.verification_method = "dependency_resolution"
                    recommendation.verification_notes = "Complete proposed set resolved; builds and tests were not run"
                    logger.info("Verification %s: resolution_verified=%s", recommendation.package, candidate)
        return remediation_plan
