"""Infer parent upgrades for pip transitive dependencies from PyPI metadata.

No environments are created and no packages are installed. Metadata candidates
remain unverified against the repository dependency graph and target environment.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

import httpx
from packaging.requirements import Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version


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
    qualifying_upgrade_versions: list[str] = field(default_factory=list)
    source: str = "pypi_metadata_inferred"
    requires_verification: bool = True

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
            raise ValueError(f"Missing PyPI release metadata: {name}=={version}")
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
    """Infer safe root upgrades by recursively checking PyPI dependency metadata."""

    def __init__(self, pypi: PyPiMetadataClient, max_candidates: int | None = None):
        self.pypi = pypi
        self.max_candidates = max_candidates

    async def shortlist(
        self, parent: str, child: str, safe_child_version: str,
        current_parent_version: str | None = None, *,
        dependency_paths: list[list[dict[str, str]]] | None = None,
        vulnerable_range: str | None = None,
    ) -> list[ParentCandidate]:
        """Return stable qualifying roots in ascending order, without installing.

        Each edge selects the latest stable release satisfying all declarations
        for that dependency. Conditional edges are conservatively retained across
        platforms/extras. Results are inference, not pip's full environment solve.
        """
        parent = canonicalize_name(parent)
        child = canonicalize_name(child)
        try:
            fixed = Version(safe_child_version)
            current = Version(current_parent_version) if current_parent_version else None
        except InvalidVersion:
            return []
        if dependency_paths and any(
            len(path) < 2
            or canonicalize_name(path[0].get("package", "")) != parent
            or canonicalize_name(path[-1].get("package", "")) != child
            for path in dependency_paths
        ):
            return []
        # Restrict recommendation lookups to edges observed on vulnerable paths.
        # With no path evidence, inspect only the direct parent -> child edge.
        relevant_edges = {}
        for path in dependency_paths or [[{"package": parent}, {"package": child}]]:
            for left, right in zip(path, path[1:]):
                relevant_edges.setdefault(canonicalize_name(left["package"]), set()).add(canonicalize_name(right["package"]))

        versions_cache = {}
        requirements_cache = {}
        expansions = 0

        async def versions(name):
            if name not in versions_cache:
                try:
                    raw_versions = await self.pypi.list_versions_descending(name)
                    parsed_versions = []
                    for raw in raw_versions:
                        try:
                            parsed = Version(raw)
                        except InvalidVersion:
                            continue
                        if not parsed.is_prerelease and not parsed.is_devrelease:
                            parsed_versions.append((parsed, raw))
                    versions_cache[name] = sorted(parsed_versions, reverse=True)
                except (httpx.HTTPError, ValueError):
                    versions_cache[name] = []
            return versions_cache[name]

        async def requirements(name, version):
            key = (name, version)
            if key not in requirements_cache:
                try:
                    values = await self.pypi.get_release_requires_dist(name, version)
                    requirements_cache[key] = [Requirement(value) for value in values]
                except (httpx.HTTPError, ValueError):
                    requirements_cache[key] = None
            return requirements_cache[key]

        def safe_target(version):
            if vulnerable_range:
                try:
                    parts = [part.strip() for part in vulnerable_range.split("||") if part.strip()]
                    return bool(parts) and not any(
                        SpecifierSet(part).contains(version, prereleases=True) for part in parts
                    )
                except InvalidSpecifier:
                    return False
            return version >= fixed

        async def safe(name, raw, ancestors):
            nonlocal expansions
            if name == child:
                return safe_target(Version(raw))
            key = (name, raw)
            if key in ancestors:
                return True
            expansions += 1
            if expansions > 500 or len(ancestors) >= 64:
                return False
            declared = await requirements(name, raw)
            if declared is None:
                return False
            grouped = {}
            for requirement in declared:
                if canonicalize_name(requirement.name) not in relevant_edges.get(name, set()):
                    continue
                if requirement.url:
                    return False
                # Retain marker-conditional dependencies rather than silently
                # hiding a path active on a different platform or via extras.
                grouped.setdefault(canonicalize_name(requirement.name), []).append(requirement.specifier)
            for dependency, constraints in grouped.items():
                options = [
                    (parsed, version) for parsed, version in await versions(dependency)
                    if all(spec.contains(parsed, prereleases=False) for spec in constraints)
                ]
                if not options:
                    return False
                if not await safe(dependency, options[0][1], ancestors | {key}):
                    return False
            return True

        result = []
        for parsed, raw in reversed(await versions(parent)):
            if current is not None and parsed <= current:
                continue
            expansions = 0
            if await safe(parent, raw, set()):
                result.append(ParentCandidate(version=raw))
                if self.max_candidates is not None and len(result) >= self.max_candidates:
                    break
        return result


class PipParentVersionResolver:
    """Select the lowest shortlisted parent upgrade using PyPI metadata only."""

    def __init__(
        self,
        shortlister: ParentVersionShortlister | None = None,
        pypi: PyPiMetadataClient | None = None,
    ):
        self._pypi = pypi
        self.shortlister = shortlister

    async def resolve(
        self,
        parent: str,
        child: str,
        safe_child_version: str,
        current_parent_version: str | None = None,
        *,
        dependency_paths: list[list[dict[str, str]]] | None = None,
        vulnerable_range: str | None = None,
    ) -> ParentResolution:
        """Return the lowest plausible stable upgrade, without installing it."""
        if self.shortlister is not None:
            candidates = await self.shortlister.shortlist(
                parent, child, safe_child_version, current_parent_version,
                dependency_paths=dependency_paths, vulnerable_range=vulnerable_range,
            )
        elif self._pypi is not None:
            candidates = await ParentVersionShortlister(self._pypi).shortlist(
                parent, child, safe_child_version, current_parent_version,
                dependency_paths=dependency_paths, vulnerable_range=vulnerable_range,
            )
        else:
            async with PyPiMetadataClient() as pypi:
                candidates = await ParentVersionShortlister(pypi).shortlist(
                    parent, child, safe_child_version, current_parent_version,
                    dependency_paths=dependency_paths, vulnerable_range=vulnerable_range,
                )

        versions = {}
        try:
            current = Version(current_parent_version) if current_parent_version else None
        except InvalidVersion:
            return ParentResolution(parent=parent, child=child)
        for candidate in candidates:
            try:
                parsed = Version(candidate.version)
            except InvalidVersion:
                continue
            if parsed.is_prerelease or parsed.is_devrelease:
                continue
            if current is not None and parsed <= current:
                continue
            versions.setdefault(parsed, candidate.version)
        qualifying = [versions[version] for version in sorted(versions)]
        minimum = qualifying[0] if qualifying else None
        return ParentResolution(
            parent=parent,
            child=child,
            resolved_version=minimum,
            minimum_upgradable_version=minimum,
            qualifying_upgrade_versions=qualifying,
        )
