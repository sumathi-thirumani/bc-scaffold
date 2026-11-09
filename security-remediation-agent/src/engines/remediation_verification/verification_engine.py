"""Contract and helpers for resolution-only verification engines."""
import logging
import shutil
import subprocess
import tempfile
import time
from contextvars import ContextVar
from abc import ABC, abstractmethod
from copy import copy
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

logger = logging.getLogger(__name__)
VERIFICATION_DEADLINE = ContextVar("verification_deadline", default=None)


class UnsupportedVerification(ValueError):
    """The available inputs, runtime or remaining budget cannot support verification."""
    pass


class ResolutionConflict(ValueError):
    """The resolver ran but did not honour these (normalized) package pins."""

    def __init__(self, packages, message):
        super().__init__(message)
        self.packages = set(packages)


@dataclass
class ManifestFile:
    """Carry original manifest/lockfile text and manifest-level verification diagnostics.

    Core idea: retain repository paths separately from temporary resolver outputs.
    Peer policy and baseline notes accompany the manifest so failures are reported
    once rather than repeated for every recommendation."""
    path: str
    content: str
    lock_path: str | None = None
    lock_content: str | None = None
    legacy_peer_deps: bool = False
    verification_note: str | None = None
    baseline_failed: bool = False


def run(args, cwd, extra_env=None):
    from ...utils.subprocess_env import minimal_subprocess_env
    executable = shutil.which(args[0])
    if executable is None:
        raise UnsupportedVerification(f"Required command is unavailable: {args[0]}")
    deadline = VERIFICATION_DEADLINE.get()
    timeout = min(300, deadline - time.monotonic()) if deadline is not None else 300
    if timeout <= 0:
        raise UnsupportedVerification("Verification timed out")
    result = subprocess.run([executable, *args[1:]], cwd=cwd, capture_output=True,
                            text=True, encoding="utf-8", errors="replace", timeout=timeout,
                            env=minimal_subprocess_env({"NO_COLOR": "1", **(extra_env or {})}))
    if result.returncode:
        diagnostics = "\n".join(part.strip() for part in (result.stderr, result.stdout) if part and part.strip())
        raise ValueError(
            f"{args[0]} resolution failed (exit {result.returncode})"
            + (f":\n{diagnostics}" if diagnostics else "")
        )


class VerificationEngine(ABC):
    """Share candidate selection and retry logic across ecosystem resolvers.

    Core idea: intersect duplicate recommendations, pin one common version per
    package, and resolve the set. Retry compatible fallbacks with accepted upgrades.
    Distribute only final resolved versions and statuses to the original
    recommendations; subclasses implement the actual resolver command."""
    @abstractmethod
    def normalize_name(self, name: str) -> str: ...

    @abstractmethod
    def run_resolver(self, root: Path, project: Path, targets: dict) -> None:
        """Resolve with exact pins (manifest -> package -> version) inside root, or raise."""

    def verify(self, manifest_file: ManifestFile, recommendations: list,
               compatible_versions: list | None = None) -> list[list[str]]:
        """Resolve one common candidate per package and share only actual results.

        Multiple advisories may recommend the same parent. A chosen version must
        occur in every recommendation's qualifying list for that manifest.
        `compatible_versions` is the reviewed compatible version per recommendation (the fallback pin).
        """
        compatible_versions = compatible_versions or [None] * len(recommendations)
        groups = {}
        for index, recommendation in enumerate(recommendations):
            for candidate in recommendation.qualifying_upgrade_versions:
                candidate.isVerified = False
                candidate.verification_status = candidate.verification_message = None
            groups.setdefault(self.normalize_name(recommendation.package), []).append(index)
        combined, combined_compatible, members = [], [], []
        for indices in groups.values():
            originals = [recommendations[i] for i in indices]
            common = set.intersection(*[
                {c.version for c in r.qualifying_upgrade_versions} for r in originals])
            if not common:
                for recommendation in originals:
                    for candidate in recommendation.qualifying_upgrade_versions:
                        candidate.verification_status = "FAILED"
                        candidate.verification_message = "No common qualifying version for this package in the manifest"
                continue
            merged = copy(originals[0])
            merged.qualifying_upgrade_versions = [copy(c) for c in originals[0].qualifying_upgrade_versions
                                                  if c.version in common]
            # A fallback must have compatibility evidence from every advisory.
            compatible = {compatible_versions[i] for i in indices}
            combined_compatible.append(next(iter(compatible)) if len(compatible) == 1
                                       and compatible <= common else None)
            combined.append(merged)
            members.append(indices)
        results = self._verify_candidates(manifest_file, combined, combined_compatible)
        verified = [[] for _ in recommendations]
        for merged, indices, versions in zip(combined, members, results):
            outcomes = {c.version: c for c in merged.qualifying_upgrade_versions}
            for index in indices:
                recommendation = recommendations[index]
                verified[index] = list(versions)
                for candidate in recommendation.qualifying_upgrade_versions:
                    outcome = outcomes.get(candidate.version)
                    if outcome is not None:
                        candidate.isVerified = outcome.isVerified
                        candidate.verification_status = outcome.verification_status
                        candidate.verification_message = outcome.verification_message
        return verified

    def _verify_candidates(self, manifest_file: ManifestFile, recommendations: list,
                           compatible_versions: list) -> list[list[str]]:
        """Return, per recommendation, the version that resolved (else empty).

        Every recommendation's minimum patched version is pinned together. Packages that fail
        are retried at their compatible version alongside all accepted upgrades.
        Every returned version belongs to a set that resolved together.
        """
        verified = [[] for _ in recommendations]
        by_version = lambda r, version: next(
            (c for c in r.qualifying_upgrade_versions if c.version == version), None)
        attempt = {i: r.qualifying_upgrade_versions[0]
                   for i, r in enumerate(recommendations) if r.qualifying_upgrade_versions}
        failed = self._verify_set(manifest_file, recommendations, attempt, verified)
        fallbacks = {}
        for i, rejected in failed.items():
            candidate = by_version(recommendations[i], compatible_versions[i])
            if candidate is not None and candidate is not rejected:
                fallbacks[i] = candidate
        if fallbacks:
            # Keep previously accepted pins in the resolver input: a fallback must
            # work with the upgrades that will be included in the final plan.
            accepted = {i: candidate for i, candidate in attempt.items() if verified[i]}
            self._verify_set(manifest_file, recommendations, {**accepted, **fallbacks}, verified)
        return verified

    def _verify_set(self, manifest_file, recommendations, candidates, verified) -> dict:
        """Pin the candidates together, dropping rejected packages until the rest resolve.

        Returns the rejected candidates by recommendation index.
        """
        rejected = {}
        remaining = dict(candidates)
        while remaining:
            versions = {i: c.version for i, c in remaining.items()}
            failed = self._failing(manifest_file, recommendations, versions)
            for i, message in failed.items():
                verified[i].clear()
                remaining[i].isVerified = False
                remaining[i].verification_status = "FAILED"
                remaining[i].verification_message = message
                rejected[i] = remaining.pop(i)
            if not failed:
                for i, candidate in remaining.items():
                    candidate.isVerified = True
                    candidate.verification_status = "SUCCESS"
                    candidate.verification_message = None
                    verified[i][:] = [candidate.version]
                break
        return rejected

    def _pins(self, recommendations, versions):
        pins = {}
        for i, version in versions.items():
            name = self.normalize_name(recommendations[i].package)
            if name in pins and pins[name] != version:
                raise ValueError(f"Conflicting verification pins for {name}")
            pins[name] = version
        return pins

    def _failing(self, manifest_file, recommendations, versions) -> dict:
        """Resolver error text by index for rejected packages; empty when the whole set resolves."""
        error = self._error(manifest_file, self._pins(recommendations, versions))
        if error is None:
            return {}
        message = str(error)
        if isinstance(error, ResolutionConflict):
            named = {i for i in versions if self.normalize_name(recommendations[i].package) in error.packages}
            if named:
                return {i: message for i in named}
        logger.info("Verification of %s failed: %s", manifest_file.path, message)
        # No culprit named: probe each package alone; if all pass alone, the combination conflicts.
        alone = {}
        for i in versions:
            single = self._error(manifest_file, self._pins(recommendations, {i: versions[i]}))
            if single is not None:
                alone[i] = str(single)
        return alone or {i: message for i in versions}

    def _error(self, manifest_file, pins):
        """The resolution error for these pins, or None when they resolve."""
        try:
            self._resolve(manifest_file, pins)
            return None
        except UnsupportedVerification:
            raise
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            return exc

    def _resolve(self, manifest_file, pins) -> None:
        deadline = VERIFICATION_DEADLINE.get()
        if deadline is not None and time.monotonic() >= deadline:
            raise UnsupportedVerification("Verification timed out")
        with tempfile.TemporaryDirectory(prefix="remediation_verification_") as tmp:
            root = Path(tmp)
            manifest = Path(PurePosixPath(manifest_file.path))
            self._write(root, manifest_file.path, manifest_file.content)
            if manifest_file.lock_path and manifest_file.lock_content is not None:
                self._write(root, manifest_file.lock_path, manifest_file.lock_content)
            self.run_resolver(root, manifest.parent, {manifest: pins})

    @staticmethod
    def _write(root, path, content):
        target = root.joinpath(*PurePosixPath(path).parts)
        if not target.resolve().is_relative_to(root.resolve()):
            raise ValueError("Verification path escapes the working directory")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
