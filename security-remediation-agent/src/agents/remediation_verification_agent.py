"""Verify each bundle's upgrade recommendations against its cached manifest files."""
import asyncio
import logging
import time
from copy import deepcopy
import re
from pathlib import PurePosixPath

from ..engines.remediation_verification.verification_engine import ManifestFile, VERIFICATION_DEADLINE
from ..engines.remediation_verification.verification_engine_factory import VerificationEngineFactory
from ..tools.ecosystem_manifest_tool import ManifestTool

logger = logging.getLogger(__name__)

VERIFICATION_TIMEOUT_SECONDS = 900

class RemediationVerificationAgent:
    """Coordinate resolution verification per declaration manifest across all bundles.

    Core idea: stage cached inputs at the repository ref, verify recommendations on
    private worker copies, and publish results only after completion. One manifest
    budget bounds subprocess execution; failed or timed-out upgrades stay unresolved."""
    def __init__(self, manifest_tool=None, engine_factory=None):
        self.manifest_tool = manifest_tool or ManifestTool()
        self.engine_factory = engine_factory or VerificationEngineFactory()

    async def verify(self, remediation_plan, repo, *, ref=None):
        """Verify once per declaration manifest and publish successful worker results back to the plan."""
        owner = repo.get("owner")
        name = repo.get("repo") or repo.get("name")
        ref = ref or repo.get("ref")
        seen = set()
        by_manifest = {}
        for bundle in remediation_plan.remediation_plan_bundles:
            for triage in bundle.packages:
                for recommendation in triage.package_upgrade_recommendations:
                    if id(recommendation) in seen:
                        continue
                    seen.add(id(recommendation))
                    recommendation.verified_version = None
                    for candidate in recommendation.qualifying_upgrade_versions:
                        candidate.isVerified, candidate.verification_status, candidate.verification_message = False, None, None
                    if recommendation.qualifying_upgrade_versions and triage.manifest_path:
                        declaration = ManifestTool.declaration_path(triage.ecosystem, triage.manifest_path) or triage.manifest_path
                        by_manifest.setdefault((triage.ecosystem, declaration), []).append(
                            (triage, recommendation))
        for (ecosystem, manifest_path), entries in by_manifest.items():
            recommendations = [recommendation for _, recommendation in entries]
            manifest_file = await self._manifest_file(owner, name, ref, ecosystem, entries[0][0].manifest_path)
            if manifest_file is None:
                logger.info("Verification skipped: manifest unavailable for %s", manifest_path)
                VerificationEngineFactory.mark_failed(recommendations, "Manifest unavailable")
                results = [[] for _ in recommendations]
            else:
                isolated_manifest, isolated_recommendations = deepcopy((manifest_file, recommendations))
                try:
                    results = await asyncio.wait_for(asyncio.to_thread(
                        self._verify_snapshot, ecosystem, isolated_manifest, isolated_recommendations),
                        VERIFICATION_TIMEOUT_SECONDS)
                    manifest_file = isolated_manifest
                    for original, checked in zip(recommendations, isolated_recommendations):
                        for candidate, outcome in zip(original.qualifying_upgrade_versions, checked.qualifying_upgrade_versions):
                            candidate.isVerified = outcome.isVerified
                            candidate.verification_status = outcome.verification_status
                            candidate.verification_message = outcome.verification_message
                except asyncio.TimeoutError:
                    logger.warning("Verification timed out for %s", manifest_path)
                    VerificationEngineFactory.mark_failed(recommendations, "Verification timed out")
                    results = [[] for _ in recommendations]
            if manifest_file and manifest_file.verification_note:
                triage = entries[0][0]
                if manifest_file.verification_note not in triage.notes:
                    triage.notes = f"{triage.notes}\n{manifest_file.verification_note}".strip()
            for (triage, recommendation), versions in zip(entries, results):
                recommendation.verified_version = versions[0] if versions else None
                logger.info("Verification %s: %s", recommendation.package,
                            f"resolution_verified={versions}" if versions else "unresolved")
                if not versions and not (manifest_file and manifest_file.baseline_failed):
                    self._note_failure(triage, recommendation)
        return remediation_plan

    def _verify_snapshot(self, ecosystem, manifest, recommendations):
        """Bound subprocess lifetimes and keep worker mutations private until completion."""
        token = VERIFICATION_DEADLINE.set(time.monotonic() + VERIFICATION_TIMEOUT_SECONDS)
        try:
            return self.engine_factory.verify(ecosystem, manifest, recommendations)
        finally:
            VERIFICATION_DEADLINE.reset(token)

    @staticmethod
    def _note_failure(triage, recommendation):
        lines = [f"Verification failed for {recommendation.package}:"]
        failures = [c for c in recommendation.qualifying_upgrade_versions if c.verification_message]
        for candidate in failures:
            lines.append(f"{candidate.version}: {candidate.verification_message}")
        if not failures:
            lines.append("no version could be verified")
        note = "\n".join(lines)
        if note not in triage.notes:
            triage.notes = f"{triage.notes}\n{note}".strip()

    async def _manifest_file(self, owner, name, ref, ecosystem, manifest_path):
        declaration = ManifestTool.declaration_path(ecosystem, manifest_path)
        content = await self.manifest_tool.get(owner, name, declaration, ref) if declaration else None
        if content is None:
            return None
        lock_path = ManifestTool.lockfile_path(ecosystem, manifest_path)
        lock_content = await self.manifest_tool.get(owner, name, lock_path, ref) if lock_path else None
        manifest = ManifestFile(declaration, content, lock_path, lock_content)
        if ecosystem.lower() in {"npm", "npm_and_yarn"}:
            # Read only peer policy; registry credentials never enter the snapshot.
            for directory in dict.fromkeys((PurePosixPath("."), PurePosixPath(declaration).parent)):
                config = await self.manifest_tool.get(owner, name, (directory / ".npmrc").as_posix(), ref)
                for line in (config or "").splitlines():
                    match = re.fullmatch(r"\s*legacy-peer-deps\s*=\s*(true|false)\s*(?:[;#].*)?", line, re.I)
                    if match:
                        manifest.legacy_peer_deps = match[1].lower() == "true"
        return manifest
