"""Fetch npm and pip manifests through the Contents API and cache them per run."""

import asyncio
import json
import logging
import os
import re
from pathlib import PurePosixPath
from urllib.parse import quote

import httpx

from ..models.security_remediation_context import SecurityRemediationCache

logger = logging.getLogger(__name__)

# Only npm and pip are supported.
LOCKFILE_NAMES = frozenset(
    {
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "Pipfile.lock",
    }
)

NPM_ECOSYSTEMS = frozenset({"npm", "npm_and_yarn", "yarn"})
PIP_ECOSYSTEMS = frozenset({"pip", "pypi", "python"})
NUGET_ECOSYSTEMS = frozenset({"nuget"})

NPM_DEPENDENCY_FIELDS = (
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
)

_REQUIREMENT_NAME = re.compile(r"^[A-Za-z0-9._-]+")


class ManifestProvider:
    """Read npm/pip manifests for one run, caching declaration manifests only.

    Reuse one instance per run and pass a commit SHA as ``ref`` for a stable
    repository snapshot. Nothing is written to disk; callers parse the returned
    JSON/text themselves.
    """

    def __init__(
        self,
        cache: SecurityRemediationCache | None = None,
        token: str | None = None,
        *,
        client: httpx.AsyncClient | None = None,
    ):
        self.cache = cache or SecurityRemediationCache()
        self._token = token or os.getenv("GITHUB_TOKEN")
        self._client = client
        self._locks: dict[tuple[str, str, str | None, str], asyncio.Lock] = {}
        # Declarations parsed from the cached manifest text, so a manifest is
        # neither re-fetched nor re-parsed for every alert that references it.
        self._declared: dict[
            tuple[str, str, str | None, str], dict[str, str | None]
        ] = {}

    @staticmethod
    def is_lockfile(path: str) -> bool:
        return PurePosixPath(path).name in LOCKFILE_NAMES

    @staticmethod
    def normalize(package: str, ecosystem: str) -> str:
        """Normalise a package name for comparison (PEP 503 rules for pip)."""
        name = package.strip().lower()
        if ecosystem.lower() in PIP_ECOSYSTEMS:
            name = re.sub(r"[-_.]+", "-", name)
        return name

    async def declared_packages(
        self, owner: str, repo: str, path: str, ref: str | None = None, ecosystem: str = "npm"
    ) -> dict[str, str | None]:
        """Return normalized declared package names and their manifest versions.

        The manifest is fetched and parsed once per repository snapshot; later
        callers are served from the run cache. An unreadable or unparsable
        manifest yields an empty set, so the caller falls back to the resolvers.
        """
        if not path:
            return {}
        key = self.cache.manifest_cache.key(owner, repo, path, ref)
        ecosystem = ecosystem.lower()
        if key in self._declared and ecosystem in self._declared[key]:
            return self._declared[key][ecosystem]
        text = await self.get(owner, repo, path, ref)
        if text is None and not self.cache.manifest_cache.has(key):
            # Transient fetch failure: leave undeclared so the caller does not
            # mistake an unreadable manifest for one that omits the package.
            return {}
        declared = self._parse_declarations(text, path, ecosystem)
        self.cache.manifest_cache.set_packages(key, ecosystem, declared)
        self._declared.setdefault(key, {})[ecosystem] = declared
        return declared

    async def repository_tree(
        self,
        owner: str,
        repo: str,
        ref: str | None = None,
    ) -> list[dict[str, str]]:
        """List repository files using the Git Trees API."""
        if not self._token:
            raise RuntimeError("GITHUB_TOKEN environment variable or token argument is required")
        if ref is None:
            repository_url = (
                f"https://api.github.com/repos/{quote(owner, safe='')}/"
                f"{quote(repo, safe='')}"
            )
            if self._client is not None:
                response = await self._client.get(
                    repository_url,
                    headers={
                        "Authorization": f"******",
                        "Accept": "application/vnd.github+json",
                        "X-GitHub-Api-Version": "2022-11-28",
                    },
                )
            else:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    response = await client.get(
                        repository_url,
                        headers={
                            "Authorization": "******",
                            "Accept": "application/vnd.github+json",
                            "X-GitHub-Api-Version": "2022-11-28",
                        },
                    )
            response.raise_for_status()
            ref = response.json().get("default_branch")
            if not ref:
                raise ValueError(
                    f"Repository metadata did not include a default branch for {owner}/{repo}"
                )
        url = f"https://api.github.com/repos/{quote(owner, safe='')}/{quote(repo, safe='')}/git/trees/{quote(ref, safe='')}"
        headers = {
            "Authorization": "******",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self._client is not None:
            response = await self._client.get(url, headers=headers, params={"recursive": "1"})
        else:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(url, headers=headers, params={"recursive": "1"})
        response.raise_for_status()
        data = response.json()
        if data.get("truncated"):
            raise ValueError(
                "Repository Git tree is truncated; cannot safely resolve .NET project path"
            )
        entries = data.get("tree", [])
        if not isinstance(entries, list):
            raise ValueError("Git Trees API did not return a tree array")
        return [
            {"path": entry["path"]}
            for entry in entries
            if entry.get("type") == "blob" and entry.get("path")
        ]

    @classmethod
    def _parse_declarations(
        cls, text: str | None, path: str, ecosystem: str
    ) -> dict[str, str | None]:
        if not text:
            return {}
        ecosystem = ecosystem.lower()
        try:
            if ecosystem in NPM_ECOSYSTEMS:
                manifest = json.loads(text)
                return {
                    cls.normalize(name, ecosystem): version
                    for field_name in NPM_DEPENDENCY_FIELDS
                    for name, version in (manifest.get(field_name) or {}).items()
                }
            if ecosystem in PIP_ECOSYSTEMS:
                return {
                    name: version
                    for name, version in cls._parse_pip_declarations(text, ecosystem)
                }
            if ecosystem in NUGET_ECOSYSTEMS:
                return cls._parse_nuget_declarations(text)
        except (ValueError, AttributeError, TypeError) as exc:
            logger.warning("Cannot parse manifest %s: %s", path, exc)
        return {}

    @classmethod
    def _parse_nuget_declarations(cls, text: str) -> dict[str, str | None]:
        """Read NuGet package references from project, props, or central props XML."""
        import xml.etree.ElementTree as ET

        try:
            root = ET.fromstring(text)
        except ET.ParseError as exc:
            logger.warning("Cannot parse NuGet project manifest: %s", exc)
            return {}

        declarations: dict[str, str | None] = {}
        for element in root.iter():
            tag = element.tag.rsplit("}", 1)[-1]
            if tag == "PackageReference":
                name = element.attrib.get("Include") or element.attrib.get("Update")
                version = element.attrib.get("Version")
                if version is None:
                    version = next(
                        (
                            child.text.strip()
                            for child in element
                            if child.tag.rsplit("}", 1)[-1] == "Version"
                            and child.text
                        ),
                        None,
                    )
                if name:
                    declarations[name.casefold()] = version
            elif tag == "PackageVersion":
                name = element.attrib.get("Include") or element.attrib.get("Update")
                version = element.attrib.get("Version")
                if name:
                    declarations[name.casefold()] = version
        return declarations

    @classmethod
    def _parse_pip_declarations(
        cls, text: str, ecosystem: str
    ) -> set[tuple[str, str | None]]:
        """Read requirement names from a requirements-style manifest."""
        names: set[tuple[str, str | None]] = set()
        for raw_line in text.splitlines():
            line = raw_line.split("#", 1)[0].strip()
            # Skip pip options (-r/-e/--hash) and URL/path requirements.
            if not line or line.startswith("-") or "://" in line:
                continue
            match = _REQUIREMENT_NAME.match(line)
            if match:
                names.add((cls.normalize(match.group(0), ecosystem), line))
        return names

    async def get(
        self,
        owner: str,
        repo: str,
        path: str,
        ref: str | None = None,
        *,
        refresh: bool = False,
    ) -> str | None:
        """Return file text for a repository snapshot, or None when unreadable.

        Declaration manifests and lockfiles are cached separately in the run's
        ``SecurityRemediationCache``. Misses are cached so an unreadable file is
        requested only once per run. Omitting ``ref`` uses the default branch;
        ``refresh=True`` repopulates a cached entry.
        """
        if not path:
            return None
        cache = (
            self.cache.manifest_lock_cache
            if self.is_lockfile(path)
            else self.cache.manifest_cache
        )
        key = cache.key(owner, repo, path, ref)
        if not refresh and cache.has(key):
            return cache.get(key)

        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            # Another coroutine may have populated the entry while waiting.
            if not refresh and cache.has(key):
                return cache.get(key)
            text, cacheable = await self._fetch(owner, repo, path, ref)
            if cacheable:
                cache.set(key, text)
            return text

    def clear_cache(self) -> None:
        """Discard cached manifests, for example before starting another run."""
        self.cache.manifest_cache.clear()
        self.cache.manifest_lock_cache.clear()
        self._declared.clear()
        self._locks.clear()

    async def _fetch(
        self, owner: str, repo: str, path: str, ref: str | None
    ) -> tuple[str | None, bool]:
        """Return ``(text, cacheable)``.

        A 404 is a definitive "file does not exist" and is cacheable. Any other
        failure (rate limit, auth, 5xx, network) is transient and must not be
        cached as a missing file.
        """
        try:
            return await self._request(owner, repo, path, ref), True
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                logger.debug("Manifest %s not found in %s/%s", path, owner, repo)
                return None, True
            logger.warning("Cannot fetch manifest %s from %s/%s: %s", path, owner, repo, exc)
        except (httpx.HTTPError, OSError, ValueError, RuntimeError) as exc:
            logger.warning("Cannot fetch manifest %s from %s/%s: %s", path, owner, repo, exc)
        return None, False

    async def _request(self, owner: str, repo: str, path: str, ref: str | None) -> str:
        path = path.lstrip("/")
        if not owner or not repo or not path or any(p in {".", "..", ""} for p in path.split("/")):
            raise ValueError("Expected owner, repository, and a repository-relative file path")
        if not self._token:
            raise RuntimeError("GITHUB_TOKEN environment variable or token argument is required")
        url = (
            f"https://api.github.com/repos/{quote(owner, safe='')}/{quote(repo, safe='')}"
            f"/contents/{quote(path, safe='/')}"
        )
        headers = {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/vnd.github.raw+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        params = {"ref": ref} if ref is not None else None
        if self._client is not None:
            response = await self._client.get(url, headers=headers, params=params)
        else:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(url, headers=headers, params=params)
        response.raise_for_status()
        if response.headers.get("content-type", "").startswith("application/json"):
            raise ValueError(f"Contents API did not return a raw file for {path}")
        return response.content.decode("utf-8-sig")
