"""Recommend a root npm upgrade that removes a vulnerable transitive package.

Recommendations use npm registry metadata without regenerating lockfiles.
"""
from __future__ import annotations

import asyncio
import logging
import shutil
import subprocess
import threading
from dataclasses import dataclass, field
from typing import ClassVar
from urllib.parse import quote

import httpx
from packaging.version import InvalidVersion, Version
from packaging.specifiers import InvalidSpecifier, SpecifierSet

from ....utils.subprocess_env import minimal_subprocess_env

logger = logging.getLogger(__name__)
NPM_REGISTRY_URL = "https://registry.npmjs.org/{name}"

try:
    from semantic_version import NpmSpec, Version as SemVersion
except ImportError:  # Without range parsing, recommendations remain unverified.
    NpmSpec = None
    SemVersion = None


@dataclass
class NpmParentResolution:
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
    DEP_FIELDS = ("dependencies", "optionalDependencies", "peerDependencies")

    # Shared across every NpmMetadataClient/NpmParentVersionResolver instance in
    # this Python process. The completed cache prevents sequential duplicates;
    # the task map prevents concurrent duplicates while the first GET is pending.
    _shared_cache: ClassVar[dict[str, dict]] = {}
    _inflight: ClassVar[dict[str, asyncio.Task[dict]]] = {}
    _cache_lock: ClassVar[threading.Lock] = threading.Lock()

    def __init__(self, client: httpx.AsyncClient | None = None):
        self._client = client
        self._owns_client = client is None

    async def __aenter__(self) -> "NpmMetadataClient":
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=30.0)
        return self

    async def __aexit__(self, *exc_info) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()

    async def get(self, package: str) -> dict:
        key = package.lower()
        loop = asyncio.get_running_loop()

        with self._cache_lock:
            cached = self._shared_cache.get(key)
            if cached is not None:
                return cached

            task = self._inflight.get(key)
            # Tasks cannot be awaited from a different event loop. This is only
            # relevant to unusual multi-thread/multi-loop applications.
            if task is None or task.get_loop() is not loop:
                task = loop.create_task(self._fetch(package))
                self._inflight[key] = task

        try:
            metadata = await asyncio.shield(task)
        except BaseException:
            # Failed/cancelled requests are not cached and can be retried.
            with self._cache_lock:
                if self._inflight.get(key) is task:
                    self._inflight.pop(key, None)
            raise

        with self._cache_lock:
            metadata = self._shared_cache.setdefault(key, metadata)
            if self._inflight.get(key) is task:
                self._inflight.pop(key, None)
        return metadata

    async def _fetch(self, package: str) -> dict:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=30.0)
            self._owns_client = True
        response = await self._client.get(
            NPM_REGISTRY_URL.format(name=quote(package, safe="")),
            headers={"Accept": "application/vnd.npm.install-v1+json"},
        )
        response.raise_for_status()
        return response.json()

    async def get_many(self, packages: list[str]) -> dict[str, dict]:
        """Fetch unique packages concurrently, reusing cached/in-flight calls."""
        unique = list(dict.fromkeys(package.lower() for package in packages))
        results = await asyncio.gather(*(self.get(package) for package in unique))
        return dict(zip(unique, results))

    @classmethod
    def clear_cache(cls) -> None:
        """Clear completed metadata, primarily for tests or explicit refreshes."""
        with cls._cache_lock:
            cls._shared_cache.clear()

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
    ) -> tuple[list[str], bool]:
        """Find newer roots whose registry dependency graph avoids the advisory.

        Inspect only known vulnerable dependency paths, selecting a stable release
        on each relevant edge. Full graph resolution belongs to verification.
        Unsupported ranges, incomplete paths and traversal limits fail closed.
        """
        if NpmSpec is None or SemVersion is None:
            return [], False
        current = _parse_version(current_parent_version)
        if current is None:
            return [], False
        if dependency_paths and any(
            len(path) < 2
            or path[0].get("package") != parent
            or path[-1].get("package") != child
            for path in dependency_paths
        ):
            return [], False
        # Restrict recommendation lookups to edges observed on vulnerable paths.
        # With no path evidence, inspect only the direct parent -> child edge.
        relevant_edges = {}
        for path in dependency_paths or [[{"package": parent}, {"package": child}]]:
            for left, right in zip(path, path[1:]):
                relevant_edges.setdefault(str.casefold(left["package"]), set()).add(str.casefold(right["package"]))

        metadata: dict[str, dict] = {}
        checked: dict[tuple[str, str], bool] = {}
        expansions = 0

        async def data(name):
            if name not in metadata:
                try:
                    metadata[name] = await self.get(name)
                except (httpx.HTTPError, ValueError):
                    logger.warning("Cannot load npm dependency metadata for %s", name)
                    metadata[name] = {}
            return metadata[name]

        def releases(package_data):
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

        async def safe(name, raw, manifest, ancestors):
            nonlocal expansions
            key = (name, raw)
            if name == child:
                return safe_target(raw)
            if key in checked:
                return checked[key]
            if key in ancestors:
                return True  # Other outgoing edges are checked by the ancestor.
            expansions += 1
            if expansions > 500 or len(ancestors) >= 64:
                return False
            requirements = {}
            for field in self.DEP_FIELDS:
                dependencies = manifest.get(field) or {}
                if not isinstance(dependencies, dict):
                    return False
                for dependency, requirement in dependencies.items():
                    if dependency.casefold() not in relevant_edges.get(name.casefold(), set()):
                        continue
                    requirements.setdefault(dependency, []).append(requirement)
            for dependency, constraints in requirements.items():
                options = releases(await data(dependency))
                try:
                    specs = [NpmSpec(requirement) for requirement in constraints]
                    options = [entry for entry in options if all(spec.match(entry[0]) for spec in specs)]
                except (ValueError, TypeError):
                    return False
                if not options:
                    return False
                _, chosen, child_manifest = options[-1]
                if not await safe(dependency, chosen, child_manifest, ancestors | {key}):
                    return False
            # Cycle-dependent successes must not be reused outside their ancestry.
            if not ancestors:
                checked[key] = True
            return True

        candidates = []
        for _, raw, manifest in releases(await data(parent)):
            if _parse_version(raw) is None or _parse_version(raw) <= current:
                continue
            expansions = 0
            if await safe(parent, raw, manifest, set()):
                candidates.append(raw)
        return candidates, True


def _node_version() -> str | None:
    node = shutil.which("node") or shutil.which("node.exe")
    if node is None:
        return None
    result = subprocess.run(
        [node, "--version"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        env=minimal_subprocess_env({"NO_COLOR": "1"}),
    )
    if result.returncode != 0:
        logger.warning("Cannot determine Node version: %s", result.stderr.strip())
        return None
    return result.stdout.strip().lstrip("vV") or None


class NpmParentVersionResolver:
    """Select parent upgrade candidates from registry metadata."""

    def __init__(
        self,
        package_text: str,
        lock_text: str,
        *,
        metadata: NpmMetadataClient | None = None,
    ):
        self.metadata = metadata

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
        if self.metadata is not None:
            return await self._resolve(
                self.metadata, parent, child, vulnerable_range, current_parent_version, fixed_version, dependency_paths=dependency_paths
            )
        async with NpmMetadataClient() as metadata:
            return await self._resolve(
                metadata, parent, child, vulnerable_range, current_parent_version, fixed_version, dependency_paths=dependency_paths
            )

    async def _resolve(
        self,
        metadata: NpmMetadataClient,
        parent: str,
        child: str,
        vulnerable_range: str,
        current_parent_version: str | None,
        fixed_version: str | None = None,
        *,
        dependency_paths: list[list[dict[str, str]]] | None = None,
    ) -> NpmParentResolution:
        node_version = await asyncio.to_thread(_node_version)
        candidates, _ = await metadata.select_candidates(
            parent,
            child,
            vulnerable_range,
            current_parent_version,
            fixed_version,
            node_version=node_version,
            dependency_paths=dependency_paths,
        )
        result = NpmParentResolution(
            parent=parent,
            child=child,
            qualifying_upgrade_versions=candidates,
            minimum_upgradable_version=candidates[0] if candidates else None,
        )
        if not candidates:
            result.action = "manual_remediation"
            result.reason = "No newer parent release with a safe registry dependency graph was found"
            return result

        # Recommend the earliest parent release with a safe inferred graph.
        result.resolved_version = candidates[0]
        result.source = "npm_registry_inferred"
        result.requires_verification = True
        result.action = "upgrade_parent"
        result.reason = "Registry dependency traversal found no affected child versions; lockfile outcome is unverified"
        return result
