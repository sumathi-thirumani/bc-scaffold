"""Recommend a root npm upgrade that removes a vulnerable transitive package.

The registry always supplies a recommendation.  A local npm installation is
used only to verify the shortlisted recommendation against package-lock.json.
"""
from __future__ import annotations

import asyncio
import json
import logging
import shutil
import subprocess
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar
from urllib.parse import quote

import httpx
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from ...utils.subprocess_env import minimal_subprocess_env
from ..relationship_resolver.npm_resolver import NpmResolver

logger = logging.getLogger(__name__)
NPM_REGISTRY_URL = "https://registry.npmjs.org/{name}"

try:
    from semantic_version import NpmSpec, Version as SemVersion
except ImportError:  # Optional: npm verification still provides ground truth.
    NpmSpec = None
    SemVersion = None


@dataclass
class NpmParentResolution:
    parent: str
    child: str
    resolved_version: str | None = None
    minimum_upgradable_version: str | None = None
    installed_child_versions: list[str] = field(default_factory=list)
    candidates_considered: list[str] = field(default_factory=list)
    source: str = "npm_registry_fallback"
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


def _maximum_non_breaking_version(
    current_version: str | None,
    candidates: list[str],
) -> str | None:
    current = _parse_version(current_version)
    if current is None:
        return None
    same_major = [
        (parsed, candidate)
        for candidate in candidates
        if (parsed := _parse_version(candidate)) is not None
        and parsed.major == current.major
    ]
    return max(same_major)[1] if same_major else None


def _is_vulnerable(version: str, vulnerable_range: str) -> bool:
    """Interpret the GitHub advisory range, conservatively on parse errors."""
    try:
        parsed = Version(version)
        alternatives = [part.strip() for part in vulnerable_range.split("||") if part.strip()]
        return any(
            SpecifierSet(part).contains(parsed, prereleases=True)
            for part in alternatives
        )
    except (InvalidVersion, InvalidSpecifier):
        return True


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
    ) -> tuple[list[str], bool, bool]:
        """Return candidates, direct-proof flag, and lockfile-refresh flag.

        The child here is the transitive vulnerable package: it is never
        queried against the npm registry. The only "safe child" signal we
        trust is the advisory's own fixed_version, taken as-is.
        """
        parent_data = await self.get(parent)
        current = _parse_version(current_parent_version)
        releases: list[tuple[Version, str, dict]] = []
        for raw, manifest in parent_data.get("versions", {}).items():
            parsed = _parse_version(raw)
            if parsed is None or parsed.is_prerelease or manifest.get("deprecated"):
                continue
            if current is not None and parsed <= current:
                continue
            node_requirement = (manifest.get("engines") or {}).get("node")
            if (
                node_version
                and isinstance(node_requirement, str)
                and not self._range_accepts(node_requirement, node_version)
            ):
                logger.info(
                    "Skipping %s@%s: Node %s does not satisfy engines.node %s",
                    parent,
                    raw,
                    node_version,
                    node_requirement,
                )
                continue
            releases.append((parsed, raw, manifest))
        releases.sort(key=lambda entry: entry[0])

        # The advisory's own fixed version is the only trusted "safe child"
        # signal; it is used as-is without any registry lookup for the child.
        safe_children = [fixed_version] if fixed_version else []

        all_versions = [raw for _, raw, _ in releases]
        if NpmSpec is None or SemVersion is None:
            return all_versions, False, False

        current_accepts_safe_child = False
        current_manifest = parent_data.get("versions", {}).get(
            current_parent_version or "", {}
        )
        current_requirement = self._dependency_requirement(current_manifest, child)
        if current_requirement:
            current_accepts_safe_child = any(
                self._range_accepts(current_requirement, version)
                for version in safe_children
            )

        direct: list[str] = []
        saw_direct = False
        for _, raw, manifest in releases:
            requirement = self._dependency_requirement(manifest, child)
            if not requirement:
                continue
            saw_direct = True
            if any(self._range_accepts(requirement, version) for version in safe_children):
                direct.append(raw)

        selected = direct if saw_direct else all_versions
        current_node_requirement = (current_manifest.get("engines") or {}).get("node")
        current_supports_node = not (
            node_version
            and isinstance(current_node_requirement, str)
            and not self._range_accepts(current_node_requirement, node_version)
        )
        if current_accepts_safe_child and current_parent_version and current_supports_node:
            selected.insert(0, current_parent_version)
        return selected, (saw_direct or current_accepts_safe_child), current_accepts_safe_child

    @classmethod
    def _dependency_requirement(cls, manifest: dict, child: str) -> str | None:
        for field in cls.DEP_FIELDS:
            value = manifest.get(field, {}).get(child)
            if value:
                return value
        return None

    @staticmethod
    def _range_accepts(requirement: str, version: str) -> bool:
        if NpmSpec is None or SemVersion is None:
            # Keep the candidate. It will either be verified by npm or marked
            # requires_verification instead of silently losing a recommendation.
            return True
        try:
            return NpmSpec(requirement).match(SemVersion.coerce(version))
        except ValueError:
            return True


class NpmLockVerifier:
    DEP_FIELDS = ("dependencies", "devDependencies", "optionalDependencies")

    def __init__(self, package_text: str, lock_text: str, timeout_seconds: int = 300):
        self.package_text = package_text
        self.lock_text = lock_text
        self.timeout_seconds = timeout_seconds

    @staticmethod
    def executable() -> str | None:
        # npm is a .cmd shim on Windows. Never use shell=True.
        return shutil.which("npm") or shutil.which("npm.cmd")

    @property
    def available(self) -> bool:
        return self.executable() is not None

    def node_version(self) -> str | None:
        node = shutil.which("node") or shutil.which("node.exe")
        if node is None:
            return None
        result = subprocess.run(
            [node, "--version"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=self.timeout_seconds,
            env=minimal_subprocess_env({"NO_COLOR": "1"}),
        )
        if result.returncode != 0:
            logger.warning("Cannot determine Node version: %s", result.stderr.strip())
            return None
        return result.stdout.strip().lstrip("vV") or None

    def verify(
        self,
        parent: str,
        parent_version: str,
        child: str,
        vulnerable_range: str,
    ) -> tuple[bool, list[str]]:
        npm = self.executable()
        if npm is None:
            return False, []

        package = json.loads(self.package_text)
        field = next(
            (name for name in self.DEP_FIELDS if parent in package.get(name, {})),
            None,
        )
        if field is None:
            return False, []
        package[field][parent] = parent_version

        with tempfile.TemporaryDirectory(prefix="npm_parent_verify_") as tmp:
            directory = Path(tmp)
            (directory / "package.json").write_text(
                json.dumps(package, indent=2), encoding="utf-8"
            )
            (directory / "package-lock.json").write_text(self.lock_text, encoding="utf-8")
            result = subprocess.run(
                [
                    npm, "install", "--package-lock-only", "--ignore-scripts",
                    "--no-audit", "--no-fund", "--legacy-peer-deps",
                ],
                cwd=directory,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout_seconds,
                env=minimal_subprocess_env({"NO_COLOR": "1"}),
            )
            if result.returncode != 0:
                logger.info(
                    "npm verification failed for %s@%s: %s",
                    parent, parent_version, result.stderr.strip(),
                )
                return False, []

            lock = json.loads(
                (directory / "package-lock.json").read_text(encoding="utf-8")
            )
            occurrences = NpmResolver(lock).resolve(child).get("occurrences", [])
            introduced = [
                occurrence
                for occurrence in occurrences
                if any(
                    source.get("package", "").lower() == parent.lower()
                    for source in occurrence.get("introducers", [])
                )
            ]
            versions = sorted(
                {o["version"] for o in introduced if o.get("version")}
            )
            remains = any(
                _is_vulnerable(o["version"], vulnerable_range)
                for o in introduced
                if o.get("version")
            )
            return not remains, versions

class NpmParentVersionResolver:
    """Select from registry metadata and optionally verify a few candidates."""

    def __init__(
        self,
        package_text: str,
        lock_text: str,
        *,
        metadata: NpmMetadataClient | None = None,
        verifier: NpmLockVerifier | None = None,
        max_verifications: int = 5,
        verify_locally: bool = False,
    ):
        self.metadata = metadata
        self.verifier = verifier or NpmLockVerifier(package_text, lock_text)
        self.max_verifications = max_verifications
        # Local verification shells out to `npm install --package-lock-only`
        # per candidate; disabled by default since it is too slow to run for
        # every transitive package's introducers across a full triage pass.
        self.verify_locally = verify_locally

    async def resolve(
        self,
        parent: str,
        child: str,
        vulnerable_range: str,
        current_parent_version: str | None = None,
        fixed_version: str | None = None,
    ) -> NpmParentResolution:
        if self.metadata is not None:
            return await self._resolve(
                self.metadata, parent, child, vulnerable_range, current_parent_version, fixed_version
            )
        async with NpmMetadataClient() as metadata:
            return await self._resolve(
                metadata, parent, child, vulnerable_range, current_parent_version, fixed_version
            )

    async def _resolve(
        self,
        metadata: NpmMetadataClient,
        parent: str,
        child: str,
        vulnerable_range: str,
        current_parent_version: str | None,
        fixed_version: str | None = None,
    ) -> NpmParentResolution:
        node_version_loader = getattr(self.verifier, "node_version", None)
        node_version = (
            await asyncio.to_thread(node_version_loader)
            if callable(node_version_loader)
            else None
        )
        candidates, direct_inference, lockfile_refresh = await metadata.select_candidates(
            parent,
            child,
            vulnerable_range,
            current_parent_version,
            fixed_version,
            node_version=node_version,
        )
        result = NpmParentResolution(
            parent=parent,
            child=child,
            candidates_considered=candidates,
            minimum_upgradable_version=_maximum_non_breaking_version(
                current_parent_version,
                candidates,
            ),
        )
        if not candidates:
            result.action = "manual_remediation"
            result.reason = "No non-deprecated newer parent release was found"
            return result

        if self.verify_locally and self.verifier.available:
            verification_candidates = (
                candidates[: self.max_verifications]
                if direct_inference
                else list(reversed(candidates[-self.max_verifications :]))
            )
            for candidate in verification_candidates:
                verified, installed = await asyncio.to_thread(
                    self.verifier.verify,
                    parent,
                    candidate,
                    child,
                    vulnerable_range,
                )
                if verified:
                    result.resolved_version = candidate
                    result.installed_child_versions = installed
                    result.source = "npm_verified"
                    result.requires_verification = False
                    result.action = (
                        "refresh_lockfile"
                        if candidate == current_parent_version
                        else "upgrade_parent"
                    )
                    result.reason = "Verified against a regenerated package-lock.json"
                    return result

        # This is the key behavior: absence/failure of npm cannot empty the recommendation.
        # For a direct dependency range, candidates are proven and minimal-first.
        # For a deeper unverified path, prefer the latest release; an arbitrary
        # early release after the current version is unlikely to contain the fix.
        result.resolved_version = candidates[0] if direct_inference else candidates[-1]
        result.source = (
            "npm_registry_inferred" if direct_inference else "npm_registry_fallback"
        )
        result.requires_verification = True
        result.action = "refresh_lockfile" if lockfile_refresh else "upgrade_parent"
        result.reason = (
            "Registry dependency range accepts a non-vulnerable child"
            if direct_inference
            else "Deep dependency path needs lockfile verification"
        )
        return result
