"""Identify a parent package version to upgrade to in order to resolve a
vulnerable pip transitive dependency.

Strategy:
1. Cheaply shortlist candidate parent versions using PyPI JSON metadata
   (``requires_dist``) so we only consider versions whose declared
   constraint on the child package can be satisfied by a safe child version.
2. For each shortlisted candidate (newest first), actually create a
   throwaway virtualenv, install the candidate parent version, and use
   ``pip inspect`` to confirm the child package resolves to a version that
   satisfies the safe-version requirement. The first candidate that
   verifies is returned.
"""
from __future__ import annotations

import asyncio
import json
import logging
import shutil
import subprocess
import sys
import tempfile
import venv
from dataclasses import dataclass, field
from pathlib import Path

import httpx
from packaging.requirements import Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from ...utils.subprocess_env import minimal_subprocess_env

logger = logging.getLogger(__name__)

PYPI_JSON_URL = "https://pypi.org/pypi/{name}/json"


@dataclass
class ParentCandidate:
    """A parent version shortlisted as a potential fix for the child vulnerability."""

    version: str
    child_specifier: str = ""


@dataclass
class ParentResolution:
    """Outcome of attempting to resolve a safe parent version."""

    parent: str
    child: str
    resolved_version: str | None = None
    minimum_upgradable_version: str | None = None
    installed_child_version: str | None = None
    candidates_considered: list[str] = field(default_factory=list)

    @property
    def resolved(self) -> bool:
        return self.resolved_version is not None


class PyPiMetadataClient:
    """Thin wrapper around the PyPI JSON API used to cheaply inspect package metadata."""

    def __init__(self, client: httpx.AsyncClient | None = None):
        self._client = client
        self._owns_client = client is None
        self._metadata_cache: dict[str, dict] = {}

    async def __aenter__(self) -> "PyPiMetadataClient":
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=30.0)
        return self

    async def __aexit__(self, *exc_info) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()

    async def get_package_metadata(self, name: str) -> dict:
        assert self._client is not None, "Use PyPiMetadataClient as an async context manager"
        key = canonicalize_name(name)
        if key not in self._metadata_cache:
            response = await self._client.get(PYPI_JSON_URL.format(name=name))
            response.raise_for_status()
            self._metadata_cache[key] = response.json()
        return self._metadata_cache[key]

    async def get_release_requires_dist(self, name: str, version: str) -> list[str]:
        """Return ``requires_dist`` for a specific release, falling back to per-release metadata."""
        metadata = await self.get_package_metadata(name)
        info = metadata.get("info", {})
        if info.get("version") == version:
            return info.get("requires_dist") or []

        releases = metadata.get("releases", {}).get(version)
        if not releases:
            return []
        # PyPI's releases listing does not include requires_dist; fetch the version-specific
        # endpoint which does.
        assert self._client is not None
        response = await self._client.get(f"https://pypi.org/pypi/{name}/{version}/json")
        response.raise_for_status()
        return response.json().get("info", {}).get("requires_dist") or []

    async def list_versions_descending(self, name: str) -> list[str]:
        metadata = await self.get_package_metadata(name)
        releases = metadata.get("releases", {})
        versions = []
        for version, files in releases.items():
            if not files:
                continue
            if any(f.get("yanked") for f in files):
                continue
            try:
                versions.append((Version(version), version))
            except InvalidVersion:
                continue
        versions.sort(key=lambda pair: pair[0], reverse=True)
        return [v for _, v in versions]


class ParentVersionShortlister:
    """Cheaply shortlists parent versions likely to resolve the child vulnerability.

    Uses PyPI ``requires_dist`` metadata only (no installs) to filter out any
    parent version whose declared constraint on the child package cannot be
    satisfied by a version at or above the required safe child version.
    """

    def __init__(self, pypi: PyPiMetadataClient, max_candidates: int = 5):
        self.pypi = pypi
        self.max_candidates = max_candidates

    @staticmethod
    def _child_specifier_from_requires(requires_dist: list[str], child: str) -> str | None:
        child_key = canonicalize_name(child)
        for req_text in requires_dist:
            try:
                req = Requirement(req_text)
            except ValueError:
                continue
            if req.marker is not None:
                # Skip extras/platform-conditional requirements; they can't be
                # cheaply verified from metadata alone and are handled later
                # by the real install step.
                continue
            if canonicalize_name(req.name) == child_key:
                return str(req.specifier)
        return None

    async def shortlist(
        self,
        parent: str,
        child: str,
        safe_child_version: str,
        current_parent_version: str | None = None,
    ) -> list[ParentCandidate]:
        """Return candidate parent versions, oldest-first, that plausibly unlock a safe child.

        Versions at or below the current parent version are skipped, so the first
        viable candidate is the minimum upgrade. A parent version is shortlisted when either:
        - it declares no constraint on the child (unconstrained, so pip is
          free to pick a safe child version), or
        - its declared specifier for the child is satisfied by
          ``safe_child_version``.
        """
        versions = reversed(await self.pypi.list_versions_descending(parent))
        try:
            safe_version = Version(safe_child_version)
        except InvalidVersion:
            logger.warning("Invalid safe version %r for %s; no parent candidates", safe_child_version, child)
            return []
        try:
            current = Version(current_parent_version) if current_parent_version else None
        except InvalidVersion:
            logger.warning("Invalid current version %r for %s; not skipping older versions",
                           current_parent_version, parent)
            current = None

        candidates: list[ParentCandidate] = []
        for version in versions:
            # list_versions_descending only returns parseable versions
            if current is not None and Version(version) <= current:
                continue
            try:
                requires_dist = await self.pypi.get_release_requires_dist(parent, version)
            except httpx.HTTPError as exc:
                logger.warning("Skipping %s==%s: metadata fetch failed: %s", parent, version, exc)
                continue

            specifier_text = self._child_specifier_from_requires(requires_dist, child)
            if specifier_text is None:
                # Parent no longer depends on the child at all, or the constraint
                # is marker-conditional; still worth a real install attempt.
                candidates.append(ParentCandidate(version=version, child_specifier=""))
            else:
                try:
                    specifier = SpecifierSet(specifier_text)
                except InvalidSpecifier:
                    logger.warning("Unparseable specifier %r for %s in %s==%s",
                                   specifier_text, child, parent, version)
                    candidates.append(ParentCandidate(version=version, child_specifier=""))
                    continue
                if specifier.contains(safe_version, prereleases=True):
                    candidates.append(ParentCandidate(version=version, child_specifier=specifier_text))

            if len(candidates) >= self.max_candidates:
                break

        return candidates


class VenvInstallVerifier:
    """Creates a throwaway venv, installs a candidate parent, and confirms the
    child package actually resolves to a safe version using ``pip inspect``."""

    def __init__(self, timeout_seconds: int = 300):
        self.timeout_seconds = timeout_seconds

    def _venv_python(self, venv_dir: Path) -> Path:
        if sys.platform == "win32":
            return venv_dir / "Scripts" / "python.exe"
        return venv_dir / "bin" / "python"

    def _run(self, args: list[str]) -> subprocess.CompletedProcess:
        # Force UTF-8 I/O and disable Rich's legacy Windows console rendering:
        # pip inspect can emit non-ASCII output (e.g. emoji in dependency
        # metadata) that crashes on Windows' default cp1252 console encoding.
        env = minimal_subprocess_env(
            {"PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8", "NO_COLOR": "1", "TERM": "dumb"}
        )
        return subprocess.run(
            args, capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=self.timeout_seconds, env=env,
        )

    def verify(self, parent: str, parent_version: str, child: str, safe_child_version: str) -> str | None:
        """Install parent==parent_version into a fresh venv and return the
        installed child version if it satisfies >= safe_child_version, else None.
        """
        with tempfile.TemporaryDirectory(prefix="pip_parent_verify_") as tmp:
            venv_dir = Path(tmp) / "venv"
            venv.EnvBuilder(with_pip=True, clear=True).create(venv_dir)
            python = self._venv_python(venv_dir)

            install = self._run(
                [str(python), "-m", "pip", "install", "--quiet", "--disable-pip-version-check",
                 "--no-input", "--only-binary=:all:", f"{parent}=={parent_version}"],
            )
            if install.returncode != 0:
                logger.info("Install failed for %s==%s: %s", parent, parent_version, install.stderr.strip())
                return None

            inspect_result = self._run(
                [str(python), "-m", "pip", "inspect", "--quiet"],
            )
            if inspect_result.returncode != 0:
                logger.warning("pip inspect failed for %s==%s: %s",
                                parent, parent_version, inspect_result.stderr.strip())
                return None

            report = json.loads(inspect_result.stdout)
            child_key = canonicalize_name(child)
            installed_version = None
            for item in report.get("installed", []):
                metadata = item.get("metadata", {})
                if canonicalize_name(metadata.get("name", "")) == child_key:
                    installed_version = metadata.get("version")
                    break

            if installed_version is None:
                logger.info("%s not installed alongside %s==%s", child, parent, parent_version)
                return None

            try:
                if Version(installed_version) >= Version(safe_child_version):
                    return installed_version
            except InvalidVersion:
                pass
            return None


class PipParentVersionResolver:
    """Finds the lowest parent version upgrade that resolves a vulnerable pip
    transitive dependency, verified against a real installation."""

    def __init__(
        self,
        shortlister: ParentVersionShortlister | None = None,
        verifier: VenvInstallVerifier | None = None,
        pypi: PyPiMetadataClient | None = None,
    ):
        self._pypi = pypi
        self.shortlister = shortlister
        self.verifier = verifier or VenvInstallVerifier()

    async def resolve(
        self,
        parent: str,
        child: str,
        safe_child_version: str,
        current_parent_version: str | None = None,
    ) -> ParentResolution:
        """Identify the minimum parent version upgrade that resolves the
        vulnerable child dependency.

        Shortlists candidates cheaply via PyPI metadata (oldest-first, above the
        current version, capped), then verifies each in a real venv install +
        ``pip inspect``. Same-major candidates are tried before breaking ones, so
        the first verified candidate is the minimum.
        """
        if self.shortlister is not None:
            shortlister = self.shortlister
            candidates = await shortlister.shortlist(
                parent, child, safe_child_version, current_parent_version
            )
        else:
            async with PyPiMetadataClient(self._pypi._client if self._pypi else None) as pypi:
                shortlister = ParentVersionShortlister(pypi)
                candidates = await shortlister.shortlist(
                    parent, child, safe_child_version, current_parent_version
                )

        resolution = ParentResolution(
            parent=parent,
            child=child,
            candidates_considered=[c.version for c in candidates],
        )

        try:
            current_major = (
                Version(current_parent_version).major
                if current_parent_version
                else None
            )
        except InvalidVersion:
            current_major = None

        non_breaking_candidates = []
        breaking_candidates = []
        for candidate in candidates:
            try:
                is_non_breaking = (
                    current_major is not None
                    and Version(candidate.version).major == current_major
                )
            except InvalidVersion:
                is_non_breaking = False
            target = non_breaking_candidates if is_non_breaking else breaking_candidates
            target.append(candidate)

        # Verify same-major candidates before a breaking upgrade; both groups are
        # oldest-first, so the first success is the minimum parent version.
        for candidate in [*non_breaking_candidates, *breaking_candidates]:
            installed_child_version = await asyncio.to_thread(
                self.verifier.verify, parent, candidate.version, child, safe_child_version
            )
            if installed_child_version is not None:
                resolution.resolved_version = candidate.version
                resolution.installed_child_version = installed_child_version
                if candidate in non_breaking_candidates:
                    resolution.minimum_upgradable_version = candidate.version
                break

        return resolution
