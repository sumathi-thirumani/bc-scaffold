"""Recommend a root npm upgrade that removes a vulnerable transitive package.

Recommendations use npm registry metadata without regenerating lockfiles.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from urllib.parse import quote

import httpx
from packaging.version import InvalidVersion, Version
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from semantic_version import NpmSpec, Version as SemVersion

logger = logging.getLogger(__name__)
NPM_REGISTRY_URL = "https://registry.npmjs.org/{name}"
MAX_CONCURRENT_REQUESTS = 10
MAX_EXPANSIONS = 500
MAX_DEPTH = 64
MAX_ATTEMPTS = 3
RETRYABLE_STATUS = {429, 500, 502, 503, 504}


class NpmMetadataError(RuntimeError):
    """Registry metadata needed for a recommendation could not be loaded."""


@dataclass
class NpmParentResolution:
    """Carry inferred npm parent candidates, bounds and the recommendation reason.

    Registry inference may avoid affected child versions but remains unverified
    until the verification engine resolves the parent upgrade in its manifest."""
    parent: str
    child: str
    resolved_version: str | None = None
    minimum_upgradable_version: str | None = None
    qualifying_upgrade_versions: list[str] = field(default_factory=list)
    source: str = "npm_registry_inferred"
    requires_verification: bool = True
    action: str = "upgrade_parent"
    reason: str = ""

    @property
    def resolved(self) -> bool:
        return self.resolved_version is not None


def _parse_version(raw: str | None) -> Version | None:
    if not raw:
        return None
    try:
        return Version(raw.lstrip("vV"))
    except InvalidVersion:
        return None


class NpmMetadataClient:
    """Share successful and in-flight npm registry requests within a run.

    Core idea: normalize package keys, coalesce concurrent lookups, bound request
    concurrency and retry transient errors. Cache successful metadata only, so failed
    requests cannot become misleading empty package information."""
    DEP_FIELDS = ("dependencies", "optionalDependencies", "peerDependencies")

    def __init__(self, client: httpx.AsyncClient | None = None, *, retry_delay: float = 0.5):
        self._client = client
        self._retry_delay = retry_delay
        self._owns_client = client is None
        self._cache: dict[str, dict] = {}
        self._inflight: dict[str, asyncio.Task[dict]] = {}
        self._semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)

    async def __aenter__(self) -> "NpmMetadataClient":
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=30.0)
        return self

    async def __aexit__(self, *exc_info) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    async def get(self, package: str) -> dict:
        """Reuse completed or pending metadata requests within this run only."""
        key = package.lower()
        if key in self._cache:
            return self._cache[key]
        task = self._inflight.get(key)
        if task is None:
            task = asyncio.create_task(self._fetch_and_cache(key))
            self._inflight[key] = task
            # Consume failures even if every waiter was cancelled.
            task.add_done_callback(lambda done: None if done.cancelled() else done.exception())
        return await asyncio.shield(task)

    async def _fetch_and_cache(self, package: str) -> dict:
        """Cache successful responses and release pending entries on every outcome."""
        try:
            metadata = await self._fetch(package)
            self._cache[package] = metadata
            return metadata
        finally:
            self._inflight.pop(package, None)

    async def _fetch(self, package: str) -> dict:
        url = NPM_REGISTRY_URL.format(name=quote(package, safe=""))
        headers = {"Accept": "application/vnd.npm.install-v1+json"}
        for attempt in range(MAX_ATTEMPTS):
            last = attempt == MAX_ATTEMPTS - 1
            try:
                async with self._semaphore:
                    if self._client is not None:
                        response = await self._client.get(url, headers=headers)
                    else:
                        # Request ownership stays with the task even if a waiter is cancelled.
                        async with httpx.AsyncClient(timeout=30.0) as client:
                            response = await client.get(url, headers=headers)
            except httpx.TransportError:
                if last:
                    raise
            else:
                if response.status_code not in RETRYABLE_STATUS or last:
                    break
            await asyncio.sleep(self._retry_delay * 2 ** attempt)
        response.raise_for_status()
        metadata = response.json()
        if not isinstance(metadata, dict):
            raise ValueError(f"Unexpected npm metadata for {package}")
        return metadata

    async def get_many(self, packages: list[str]) -> dict[str, dict]:
        """Fetch unique packages concurrently, reusing cached/in-flight calls."""
        unique = list(dict.fromkeys(package.lower() for package in packages))
        results = await asyncio.gather(*(self.get(package) for package in unique))
        return dict(zip(unique, results))

    async def select_candidates(
        self,
        parent: str,
        child: str,
        vulnerable_range: str,
        current_parent_version: str | None,
        fixed_version: str | None = None,
        node_version: str | None = None,
        *,
        dependency_paths: list[list[dict[str, str]]] | None = None,
    ) -> list[str]:
        """Find newer roots whose registry dependency graph avoids the advisory.

        Inspect only known vulnerable dependency paths, selecting a stable release
        on each relevant edge. Full graph resolution belongs to verification.
        Unsupported ranges, incomplete paths and traversal limits fail closed.
        Raises NpmMetadataError when registry metadata cannot be loaded.
        """
        current = _parse_version(current_parent_version)
        if current is None:
            return []
        if dependency_paths and any(
            len(path) < 2
            or path[0].get("package") != parent
            or path[-1].get("package") != child
            for path in dependency_paths
        ):
            return []
        # Restrict recommendation lookups to edges observed on vulnerable paths.
        # With no path evidence, inspect only the direct parent -> child edge.
        relevant_edges: dict[str, set[str]] = {}
        for path in dependency_paths or [[{"package": parent}, {"package": child}]]:
            for left, right in zip(path, path[1:]):
                relevant_edges.setdefault(left["package"].casefold(), set()).add(right["package"].casefold())

        names = relevant_edges.keys() | {n for v in relevant_edges.values() for n in v}
        try:
            metadata = await self.get_many(sorted(names))
        except (httpx.HTTPError, ValueError) as error:
            raise NpmMetadataError(f"Cannot load npm metadata for {parent}: {error}") from error
        release_cache: dict[str, list] = {}
        checked: set[tuple[str, str]] = set()
        expansions = 0

        def releases(name):
            key = name.casefold()
            if key not in release_cache:
                release_cache[key] = _releases(metadata.get(key), node_version)
            return release_cache[key]

        def safe_target(raw):
            try:
                version = Version(raw)
                if vulnerable_range:
                    return not any(
                        SpecifierSet(part.strip()).contains(version, prereleases=True)
                        for part in vulnerable_range.split("||") if part.strip()
                    )
                return bool(fixed_version) and version >= Version(fixed_version)
            except (InvalidVersion, InvalidSpecifier, TypeError):
                return False

        def safe(name, raw, manifest, ancestors):
            """Return (is_safe, ancestor keys a success depended on through cycles)."""
            nonlocal expansions
            key = (name, raw)
            if name == child:
                return safe_target(raw), frozenset()
            if key in checked:
                return True, frozenset()
            if key in ancestors:
                return True, frozenset({key})  # Other edges are checked by the ancestor.
            expansions += 1
            if expansions > MAX_EXPANSIONS or len(ancestors) >= MAX_DEPTH:
                return False, frozenset()
            requirements: dict[str, list] = {}
            for dep_field in self.DEP_FIELDS:
                dependencies = manifest.get(dep_field) or {}
                if not isinstance(dependencies, dict):
                    return False, frozenset()
                for dependency, requirement in dependencies.items():
                    if dependency.casefold() not in relevant_edges.get(name.casefold(), set()):
                        continue
                    requirements.setdefault(dependency, []).append(requirement)
            cycles: frozenset = frozenset()
            for dependency, constraints in requirements.items():
                options = releases(dependency)
                try:
                    specs = [NpmSpec(requirement) for requirement in constraints]
                    options = [entry for entry in options if all(spec.match(entry[0]) for spec in specs)]
                except (ValueError, TypeError):
                    return False, frozenset()
                if not options:
                    return False, frozenset()
                _, chosen, child_manifest = options[-1]
                ok, hit = safe(dependency, chosen, child_manifest, ancestors | {key})
                if not ok:
                    return False, frozenset()
                cycles |= hit
            # Successes that relied on an outer ancestor must not be reused elsewhere.
            if cycles <= {key}:
                checked.add(key)
            return True, cycles - {key}

        candidates = []
        for _, raw, manifest in releases(parent):
            if _parse_version(raw) is None or _parse_version(raw) <= current:
                continue
            expansions = 0
            if safe(parent, raw, manifest, frozenset())[0]:
                candidates.append(raw)
        return candidates


def _releases(package_data, node_version):
    result = []
    if not isinstance(package_data, dict):
        return result
    versions = package_data.get("versions") or {}
    if not isinstance(versions, dict):
        return result
    for raw, manifest in versions.items():
        if not isinstance(manifest, dict):
            continue
        try:
            version = SemVersion(raw)
            if version.prerelease or manifest.get("deprecated"):
                continue
            engines = manifest.get("engines") or {}
            if not isinstance(engines, dict):
                logger.debug("Skipping npm release %s with malformed engines metadata", raw)
                continue
            engine = engines.get("node")
            if node_version and engine and not NpmSpec(engine).match(SemVersion(node_version)):
                continue
            result.append((version, raw, manifest))
        except (ValueError, TypeError):
            continue
    return sorted(result, key=lambda entry: entry[0])


class NpmParentVersionResolver:
    """Select parent upgrade candidates from registry metadata.

    Pass node_version (for example from the repo's .nvmrc or engines.node) to
    drop releases that do not support that runtime; by default no engine filter applies.
    """

    def __init__(
        self,
        *,
        metadata: NpmMetadataClient | None = None,
        node_version: str | None = None,
    ):
        self.metadata = metadata or NpmMetadataClient()
        self.node_version = node_version.lstrip("vV") if node_version else None

    async def resolve(
        self,
        parent: str,
        child: str,
        vulnerable_range: str,
        current_parent_version: str | None = None,
        fixed_version: str | None = None,
        *,
        dependency_paths: list[list[dict[str, str]]] | None = None,
    ) -> NpmParentResolution:
        result = NpmParentResolution(parent=parent, child=child)
        try:
            candidates = await self.metadata.select_candidates(
                parent,
                child,
                vulnerable_range,
                current_parent_version,
                fixed_version,
                node_version=self.node_version,
                dependency_paths=dependency_paths,
            )
        except NpmMetadataError as error:
            logger.warning("npm recommendation unverified for %s: %s", parent, error)
            result.action = "metadata_unavailable"
            result.reason = f"Registry metadata could not be loaded: {error}"
            return result
        result.qualifying_upgrade_versions = candidates
        if not candidates:
            result.action = "manual_remediation"
            result.reason = "No newer parent release with a safe registry dependency graph was found"
            current = _parse_version(current_parent_version)
            if current is not None:
                try:
                    releases = _releases(await self.metadata.get(parent), self.node_version)
                except (httpx.HTTPError, ValueError) as error:
                    result.action = "metadata_unavailable"
                    result.reason = f"Registry metadata could not be loaded: {error}"
                    return result
                if releases and not any(_parse_version(raw) > current for _, raw, _ in releases
                                        if _parse_version(raw) is not None):
                    result.reason = (
                        f"No newer eligible stable parent release exists: current={current_parent_version}, "
                        f"latest eligible={releases[-1][1]}. "
                        "Transitive dependency refreshes or overrides require separate validation."
                    )
            return result

        # Recommend the earliest parent release with a safe inferred graph.
        result.minimum_upgradable_version = candidates[0]
        result.resolved_version = candidates[0]
        result.reason = "Registry dependency traversal found no affected child versions; lockfile outcome is unverified"
        return result
