"""Infer parent upgrades for pip transitive dependencies from PyPI metadata.

No environments are created and no packages are installed. Metadata candidates
remain unverified against the repository dependency graph and target environment.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from urllib.parse import quote

import httpx
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version


logger = logging.getLogger(__name__)

PYPI_JSON_URL = "https://pypi.org/pypi/{name}/json"
PYPI_RELEASE_JSON_URL = "https://pypi.org/pypi/{name}/{version}/json"
MAX_CONCURRENT_REQUESTS = 10
MAX_ATTEMPTS = 3
RETRYABLE_STATUS = {429, 500, 502, 503, 504}
MAX_EXPANSIONS = 500
MAX_DEPTH = 64
# Markers are evaluated across these environments; a release must be safe in each.
MARKER_ENVIRONMENTS = [
    {
        "python_version": f"3.{minor}",
        "python_full_version": f"3.{minor}.0",
        "sys_platform": sys_platform,
        "platform_system": system,
        "os_name": "nt" if sys_platform == "win32" else "posix",
        "extra": "",
    }
    for minor in range(9, 14)
    for sys_platform, system in (("linux", "Linux"), ("win32", "Windows"), ("darwin", "Darwin"))
]


class PyPiMetadataError(RuntimeError):
    """PyPI metadata needed for a recommendation could not be loaded."""


@dataclass
class ParentCandidate:
    """A parent version shortlisted as a potential fix for the child vulnerability."""

    version: str


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
    action: str = "upgrade_parent"
    reason: str = ""

    @property
    def resolved(self) -> bool:
        return self.resolved_version is not None


class PyPiMetadataClient:
    """Thin wrapper around the PyPI JSON API with per-run caching and retries."""

    def __init__(self, client: httpx.AsyncClient | None = None, *, retry_delay: float = 0.5):
        self._client = client
        self._owns_client = client is None
        self._retry_delay = retry_delay
        self._tasks: dict[str, asyncio.Task[dict]] = {}
        self._semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)

    async def __aenter__(self) -> "PyPiMetadataClient":
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=30.0)
        return self

    async def __aexit__(self, *exc_info) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _get_json(self, url: str) -> dict:
        """Share completed and pending requests; failures are never cached."""
        task = self._tasks.get(url)
        if task is None:
            task = asyncio.ensure_future(self._fetch(url))
            self._tasks[url] = task
        try:
            return await asyncio.shield(task)
        except Exception:
            if self._tasks.get(url) is task and task.done():
                self._tasks.pop(url, None)
            raise

    async def _fetch(self, url: str) -> dict:
        try:
            for attempt in range(MAX_ATTEMPTS):
                last = attempt == MAX_ATTEMPTS - 1
                try:
                    async with self._semaphore:
                        if self._client is not None:
                            response = await self._client.get(url)
                        else:
                            async with httpx.AsyncClient(timeout=30.0) as client:
                                response = await client.get(url)
                except httpx.TransportError:
                    if last:
                        raise
                else:
                    if response.status_code not in RETRYABLE_STATUS or last:
                        break
                await asyncio.sleep(self._retry_delay * 2 ** attempt)
            response.raise_for_status()
            data = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise PyPiMetadataError(f"PyPI lookup failed for {url}: {exc}") from exc
        if not isinstance(data, dict):
            raise PyPiMetadataError(f"Unexpected PyPI metadata from {url}")
        return data

    async def get_package_metadata(self, name: str) -> dict:
        return await self._get_json(PYPI_JSON_URL.format(name=quote(canonicalize_name(name), safe="")))

    async def get_release_requires_dist(self, name: str, version: str) -> list[str]:
        """Return ``requires_dist`` for a specific release."""
        metadata = await self.get_package_metadata(name)
        info = metadata.get("info") or {}
        if info.get("version") == version:
            return info.get("requires_dist") or []
        if not (metadata.get("releases") or {}).get(version):
            raise PyPiMetadataError(f"Missing PyPI release metadata: {name}=={version}")
        # The releases listing omits requires_dist; the version endpoint has it.
        data = await self._get_json(PYPI_RELEASE_JSON_URL.format(
            name=quote(canonicalize_name(name), safe=""), version=quote(version, safe=""),
        ))
        return (data.get("info") or {}).get("requires_dist") or []

    async def list_versions_descending(self, name: str) -> list[str]:
        metadata = await self.get_package_metadata(name)
        versions = []
        for version, files in (metadata.get("releases") or {}).items():
            # A release is yanked only when every file is; unreleased ones have no files.
            if not files or all(f.get("yanked") for f in files):
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
        self, parent: str, child: str, safe_child_version: str | None,
        current_parent_version: str | None = None, *,
        dependency_paths: list[list[dict[str, str]]] | None = None,
        vulnerable_range: str | None = None,
    ) -> list[ParentCandidate]:
        """Return stable qualifying roots in ascending order, without installing.

        Each edge selects the latest stable release satisfying all declarations
        that apply together in a sampled environment (see MARKER_ENVIRONMENTS).
        Extras are not installed. Results are inference, not pip's environment solve.
        Raises PyPiMetadataError when metadata cannot be loaded.
        """
        parent = canonicalize_name(parent)
        child = canonicalize_name(child)
        try:
            fixed = Version(safe_child_version) if safe_child_version else None
            current = Version(current_parent_version) if current_parent_version else None
        except (InvalidVersion, TypeError):
            return []
        if fixed is None and not vulnerable_range:
            return []
        if dependency_paths and any(
            len(path) < 2
            or canonicalize_name(path[0].get("package", "")) != parent
            or canonicalize_name(path[-1].get("package", "")) != child
            for path in dependency_paths
        ):
            return []
        # Restrict lookups to edges observed on vulnerable paths.
        # With no path evidence, inspect only the direct parent -> child edge.
        relevant_edges: dict[str, set[str]] = {}
        for path in dependency_paths or [[{"package": parent}, {"package": child}]]:
            for left, right in zip(path, path[1:]):
                relevant_edges.setdefault(canonicalize_name(left["package"]), set()).add(
                    canonicalize_name(right["package"])
                )

        versions_cache: dict[str, list[tuple[Version, str]]] = {}
        checked: set[tuple[str, str]] = set()
        expansions = 0

        async def versions(name):
            if name not in versions_cache:
                parsed_versions = []
                for raw in await self.pypi.list_versions_descending(name):
                    try:
                        parsed = Version(raw)
                    except InvalidVersion:
                        continue
                    if not parsed.is_prerelease and not parsed.is_devrelease:
                        parsed_versions.append((parsed, raw))
                versions_cache[name] = parsed_versions
            return versions_cache[name]

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

        def constraint_sets(declared, name):
            """Distinct specifier sets per dependency across sampled environments."""
            wanted = relevant_edges.get(name, set())
            relevant = []
            for value in declared:
                try:
                    requirement = Requirement(value)
                except InvalidRequirement:
                    return None
                if canonicalize_name(requirement.name) in wanted:
                    relevant.append(requirement)
            result: dict[str, set[frozenset[str]]] = {}
            for requirement in relevant:
                if requirement.url:
                    return None
            for environment in MARKER_ENVIRONMENTS:
                active: dict[str, set[str]] = {}
                for requirement in relevant:
                    if requirement.marker is None or requirement.marker.evaluate(environment):
                        active.setdefault(canonicalize_name(requirement.name), set()).add(
                            str(requirement.specifier)
                        )
                for dependency, specs in active.items():
                    result.setdefault(dependency, set()).add(frozenset(specs))
            return result

        async def safe(name, raw, ancestors):
            """Return (is_safe, ancestor keys a success relied on through cycles)."""
            nonlocal expansions
            if name == child:
                return safe_target(Version(raw)), frozenset()
            key = (name, raw)
            if key in checked:
                return True, frozenset()
            if key in ancestors:
                return True, frozenset({key})  # Other edges are checked by the ancestor.
            expansions += 1
            if expansions > MAX_EXPANSIONS or len(ancestors) >= MAX_DEPTH:
                return False, frozenset()
            declared = await self.pypi.get_release_requires_dist(name, raw)
            grouped = constraint_sets(declared, name)
            if grouped is None:
                return False, frozenset()
            cycles: frozenset = frozenset()
            for dependency, spec_sets in grouped.items():
                available = await versions(dependency)
                for specs in spec_sets:
                    try:
                        parsed_specs = [SpecifierSet(spec) for spec in specs]
                    except InvalidSpecifier:
                        return False, frozenset()
                    options = [
                        (parsed, version) for parsed, version in available
                        if all(spec.contains(parsed, prereleases=False) for spec in parsed_specs)
                    ]
                    if not options:
                        return False, frozenset()
                    ok, hit = await safe(dependency, options[0][1], ancestors | {key})
                    if not ok:
                        return False, frozenset()
                    cycles |= hit
            # Successes that relied on an outer ancestor must not be reused elsewhere.
            if cycles <= {key}:
                checked.add(key)
            return True, cycles - {key}

        names = set(relevant_edges) | {n for targets in relevant_edges.values() for n in targets}
        await asyncio.gather(*(versions(name) for name in names))

        result = []
        for parsed, raw in reversed(await versions(parent)):
            if current is not None and parsed <= current:
                continue
            expansions = 0
            if (await safe(parent, raw, frozenset()))[0]:
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
        self.shortlister = shortlister or ParentVersionShortlister(pypi or PyPiMetadataClient())

    async def resolve(
        self,
        parent: str,
        child: str,
        safe_child_version: str | None,
        current_parent_version: str | None = None,
        *,
        dependency_paths: list[list[dict[str, str]]] | None = None,
        vulnerable_range: str | None = None,
    ) -> ParentResolution:
        """Return the lowest plausible stable upgrade, without installing it."""
        result = ParentResolution(parent=parent, child=child)
        try:
            candidates = await self.shortlister.shortlist(
                parent, child, safe_child_version, current_parent_version,
                dependency_paths=dependency_paths, vulnerable_range=vulnerable_range,
            )
        except PyPiMetadataError as exc:
            logger.warning("pip recommendation unverified for %s: %s", parent, exc)
            result.action = "metadata_unavailable"
            result.reason = f"Registry metadata could not be loaded: {exc}"
            return result
        qualifying = [candidate.version for candidate in candidates]
        if not qualifying:
            result.action = "manual_remediation"
            result.reason = "No newer parent release with a safe registry dependency graph was found"
            return result
        result.qualifying_upgrade_versions = qualifying
        result.minimum_upgradable_version = result.resolved_version = qualifying[0]
        result.reason = "Registry dependency metadata avoids the affected child versions; outcome is unverified"
        return result
