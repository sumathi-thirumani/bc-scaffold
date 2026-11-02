"""Fetch and cache raw repository manifests and lockfiles from GitHub."""

import asyncio
import base64
import binascii
import contextlib
import copy
import logging
import os
import re
import time
from pathlib import PurePosixPath
from urllib.parse import quote

import httpx

from ..models.security_remediation_context import SecurityRemediationCache

logger = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"
API_VERSION = "2022-11-28"

NPM_LOCKFILES = frozenset({"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"})
NUGET_LOCKFILES = frozenset({"packages.lock.json"})
LOCKFILE_NAMES = NPM_LOCKFILES | NUGET_LOCKFILES | {"Pipfile.lock", "poetry.lock"}
NUGET_DECLARATION_SUFFIXES = frozenset({".csproj", ".fsproj", ".vbproj", ".props", ".targets"})
NPM_ECOSYSTEMS = frozenset({"npm", "npm_and_yarn", "yarn"})
PIP_ECOSYSTEMS = frozenset({"pip", "pypi", "python"})
POETRY_ECOSYSTEMS = frozenset({"poetry"})
NUGET_ECOSYSTEMS = frozenset({"nuget"})
MAX_CONCURRENT_REQUESTS = 8
MAX_ATTEMPTS = 3
RETRY_BASE_DELAY = 1.0
MAX_RETRY_DELAY = 60.0


class OfflineCacheMiss(httpx.HTTPError):
    """Raised when an offline ManifestTool would have hit the network."""


class ManifestTool:
    """Fetch, cache, and return raw repository file content.

    This class intentionally does not parse manifests, lockfiles, or dependency
    declarations. Consumers that need structured data own that parsing logic.
    """

    def __init__(
        self,
        cache: SecurityRemediationCache | None = None,
        token: str | None = None,
        *,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._cache = cache or SecurityRemediationCache()
        self._token = token if token is not None else os.environ.get("GITHUB_TOKEN")
        self._client = client
        self._owned_client: httpx.AsyncClient | None = None
        self._semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
        self._sleep = asyncio.sleep
        self._locks: dict[tuple, list] = {}
        self._refs: dict[tuple[str, str], str | None] = {}
        self._ref_lock = asyncio.Lock()
        self._visible: dict[tuple[str, str], bool] = {}
        self._trees: dict[tuple[str, str, str], list[dict[str, str]]] = {}
        self._warned_no_token = False
        self._offline = False

    @property
    def cache(self) -> SecurityRemediationCache:
        return self._cache

    @property
    def is_offline(self) -> bool:
        return self._offline

    def offline(self) -> "ManifestTool":
        """Return a cache-only view sharing this tool's state."""
        view = copy.copy(self)
        view._offline = True
        return view

    @staticmethod
    def is_lockfile(path: str | None) -> bool:
        return bool(path) and PurePosixPath(path).name in LOCKFILE_NAMES

    @classmethod
    def declaration_path(cls, ecosystem: str, manifest_path: str | None) -> str | None:
        """Map an alert path to its conventional declaration-file path."""
        if not manifest_path:
            return None
        ecosystem = (ecosystem or "").lower()
        path = PurePosixPath(manifest_path.replace("\\", "/").strip("/"))
        name = path.name
        if ecosystem in NPM_ECOSYSTEMS:
            if name == "package.json":
                return path.as_posix()
            if name in NPM_LOCKFILES:
                return path.with_name("package.json").as_posix()
            return None
        if ecosystem in PIP_ECOSYSTEMS:
            if path.suffix == ".txt":
                return path.with_suffix(".in").as_posix()
            if name == "Pipfile.lock":
                return path.with_name("Pipfile").as_posix()
            if name == "poetry.lock":
                return path.with_name("pyproject.toml").as_posix()
            return path.as_posix()
        if ecosystem in POETRY_ECOSYSTEMS:
            if name in {"poetry.lock", "pyproject.toml"}:
                return path.with_name("pyproject.toml").as_posix()
            return None
        if ecosystem in NUGET_ECOSYSTEMS:
            if name.lower() == "packages.config" or path.suffix.lower() in NUGET_DECLARATION_SUFFIXES:
                return path.as_posix()
            return None
        return None

    @classmethod
    def lockfile_path(cls, ecosystem: str, manifest_path: str | None) -> str | None:
        """Map an alert path to the lockfile path used by downstream consumers."""
        if not manifest_path:
            return None
        ecosystem = (ecosystem or "").lower()
        path = PurePosixPath(manifest_path.replace("\\", "/").strip("/"))
        if ecosystem in POETRY_ECOSYSTEMS:
            return path.with_name("poetry.lock").as_posix()
        if ecosystem in PIP_ECOSYSTEMS:
            return path.as_posix()
        if ecosystem in NPM_ECOSYSTEMS:
            if path.name in NPM_LOCKFILES:
                return path.as_posix()
            return path.with_name("package-lock.json").as_posix()
        return None

    @classmethod
    def npm_recommendation_paths(cls, manifest_path: str) -> tuple[str, str]:
        path = PurePosixPath(manifest_path.replace("\\", "/").strip("/"))
        lock = path if path.name in {"package-lock.json", "npm-shrinkwrap.json"} \
            else path.with_name("package-lock.json")
        return path.with_name("package.json").as_posix(), lock.as_posix()

    UNPARSED_LOCKFILES = frozenset({"pnpm-lock.yaml", "Pipfile.lock"})

    @classmethod
    def relationship_resolver_kind(cls, ecosystem: str, lock_path: str | None) -> str | None:
        if not lock_path:
            return None
        name = PurePosixPath(lock_path).name
        ecosystem = (ecosystem or "").lower()
        if name in cls.UNPARSED_LOCKFILES:
            return None
        if name == "poetry.lock" and ecosystem in PIP_ECOSYSTEMS | POETRY_ECOSYSTEMS:
            return "poetry"
        if name == "yarn.lock" and ecosystem in NPM_ECOSYSTEMS:
            return "yarn"
        if ecosystem in NPM_ECOSYSTEMS:
            return "npm"
        if ecosystem in PIP_ECOSYSTEMS:
            return "pip"
        if ecosystem in POETRY_ECOSYSTEMS:
            return "poetry"
        return None

    @classmethod
    def triage_paths(cls, ecosystem: str, manifest_path: str | None) -> list[str]:
        """Return raw files downstream relationship and recommendation logic may read."""
        ecosystem = (ecosystem or "").lower()
        lock = cls.lockfile_path(ecosystem, manifest_path)
        if not lock:
            return []
        kind = cls.relationship_resolver_kind(ecosystem, lock)
        paths = [lock] if kind else []
        if kind == "poetry":
            paths.append(PurePosixPath(lock).with_name("pyproject.toml").as_posix())
        if ecosystem in NPM_ECOSYSTEMS and manifest_path:
            paths.extend(cls.npm_recommendation_paths(manifest_path))
        return list(dict.fromkeys(paths))

    @staticmethod
    def normalize(name: str, ecosystem: str) -> str:
        ecosystem = (ecosystem or "").lower()
        if ecosystem in PIP_ECOSYSTEMS | POETRY_ECOSYSTEMS:
            return re.sub(r"[-_.]+", "-", name).lower()
        if ecosystem in NUGET_ECOSYSTEMS:
            return name.casefold()
        return name.lower()

    async def resolve_ref(self, owner: str, repo: str, ref: str | None = None) -> str | None:
        if ref is not None:
            return ref
        repo_key = (owner.lower(), repo.lower())
        if repo_key in self._refs:
            return self._refs[repo_key]
        if self._offline:
            return None
        async with self._ref_lock:
            if repo_key in self._refs:
                return self._refs[repo_key]
            if not self._has_token():
                return None
            url = f"{GITHUB_API}/repos/{quote(owner, safe='')}/{quote(repo, safe='')}/commits/HEAD"
            sha: str | None = None
            try:
                response = await self._send(url, "application/vnd.github.sha")
                response.raise_for_status()
                sha = response.text.strip() or None
            except (httpx.HTTPError, OSError) as exc:
                logger.warning(
                    "Could not pin HEAD for %s/%s; reading the default branch unpinned: %s",
                    owner, repo, exc,
                )
            self._refs[repo_key] = sha
            if sha:
                self._visible[repo_key] = True
            return sha

    @contextlib.asynccontextmanager
    async def _key_lock(self, key: tuple):
        entry = self._locks.setdefault(key, [asyncio.Lock(), 0])
        entry[1] += 1
        try:
            async with entry[0]:
                yield
        finally:
            entry[1] -= 1
            if entry[1] == 0 and self._locks.get(key) is entry:
                del self._locks[key]

    async def get(
        self,
        owner: str,
        repo: str,
        path: str,
        ref: str | None = None,
        *,
        refresh: bool = False,
    ) -> str | None:
        """Return raw UTF-8 file content, using the run-scoped cache."""
        if not self._has_token():
            return None
        ref = await self.resolve_ref(owner, repo, ref)
        cache = self._cache.manifest_lock_cache if self.is_lockfile(path) else self._cache.manifest_cache
        key = cache.key(owner, repo, path, ref)
        async with self._key_lock(("content", *key)):
            if refresh:
                cache.discard(key)
            elif cache.has(key):
                return cache.get(key)
            if self._offline:
                logger.debug("Cache miss for %s in %s/%s@%s (offline)", path, owner, repo, ref)
                return None
            text, cacheable = await self._fetch(owner, repo, path, ref)
            if cacheable:
                cache.set(key, text)
            return text

    async def repository_tree(self, owner: str, repo: str, ref: str | None = None) -> list[dict[str, str]]:
        if not self._has_token():
            raise ValueError("GITHUB_TOKEN is required to list the repository tree")
        ref = await self.resolve_ref(owner, repo, ref)
        base = f"{GITHUB_API}/repos/{quote(owner, safe='')}/{quote(repo, safe='')}"
        try:
            if ref is None:
                response = await self._send(base, "application/vnd.github+json")
                response.raise_for_status()
                ref = response.json().get("default_branch")
                if not ref:
                    raise ValueError(f"Cannot determine default branch for {owner}/{repo}")
            tree_key = (owner.lower(), repo.lower(), ref)
            if tree_key in self._trees:
                return self._trees[tree_key]
            response = await self._send(
                f"{base}/git/trees/{quote(ref, safe='')}",
                "application/vnd.github+json",
                params={"recursive": "1"},
            )
            response.raise_for_status()
            payload = response.json()
        except httpx.HTTPError as exc:
            raise ValueError(f"Cannot list repository tree for {owner}/{repo}@{ref}: {exc}") from exc
        if not isinstance(payload, dict) or not isinstance(payload.get("tree"), list):
            raise ValueError("Unexpected repository tree response")
        if payload.get("truncated"):
            raise ValueError(f"Repository tree for {owner}/{repo} is truncated; cannot list files safely")
        entries = [
            {"path": entry["path"]}
            for entry in payload["tree"]
            if isinstance(entry, dict) and entry.get("type") == "blob" and entry.get("path")
        ]
        self._trees[tree_key] = entries
        return entries

    def clear_cache(self) -> None:
        self._cache.manifest_cache.clear()
        self._cache.manifest_lock_cache.clear()
        self._trees.clear()
        self._refs.clear()
        self._visible.clear()

    def _has_token(self) -> bool:
        if self._token:
            return True
        if not self._warned_no_token:
            logger.warning("GITHUB_TOKEN is not set; manifest lookups are disabled")
            self._warned_no_token = True
        return False

    def _headers(self, accept: str) -> dict[str, str]:
        return {
            "Accept": accept,
            "Authorization": f"Bearer {self._token}",
            "X-GitHub-Api-Version": API_VERSION,
        }

    async def _send(self, url: str, accept: str, params: dict | None = None) -> httpx.Response:
        if self._offline:
            raise OfflineCacheMiss(f"Offline ManifestTool refused network request: {url}")
        client = self._client or self._get_owned_client()
        async with self._semaphore:
            for attempt in range(1, MAX_ATTEMPTS + 1):
                try:
                    response = await client.get(
                        url,
                        headers=self._headers(accept),
                        params=params,
                    )
                except httpx.TransportError:
                    if attempt == MAX_ATTEMPTS:
                        raise
                    await self._sleep(self._retry_delay(None, attempt))
                    continue
                if attempt == MAX_ATTEMPTS or not self._is_retryable(response):
                    return response
                await self._sleep(self._retry_delay(response, attempt))
        raise RuntimeError("unreachable")

    def _get_owned_client(self) -> httpx.AsyncClient:
        if self._owned_client is None:
            self._owned_client = httpx.AsyncClient(timeout=30)
        return self._owned_client

    async def aclose(self) -> None:
        if self._offline:
            return
        if self._owned_client is not None:
            await self._owned_client.aclose()
            self._owned_client = None

    @staticmethod
    def _is_retryable(response: httpx.Response) -> bool:
        status = response.status_code
        if status == 429 or status >= 500:
            return True
        return status == 403 and response.headers.get("x-ratelimit-remaining") == "0"

    @staticmethod
    def _retry_delay(response: httpx.Response | None, attempt: int) -> float:
        delay = RETRY_BASE_DELAY * (2 ** (attempt - 1))
        if response is not None:
            retry_after = response.headers.get("retry-after")
            reset = response.headers.get("x-ratelimit-reset")
            with contextlib.suppress(ValueError):
                if retry_after is not None:
                    delay = max(delay, float(retry_after))
                elif reset is not None:
                    delay = max(delay, float(reset) - time.time())
        return max(0.0, min(delay, MAX_RETRY_DELAY))

    async def _fetch(self, owner: str, repo: str, path: str, ref: str | None) -> tuple[str | None, bool]:
        try:
            response = await self._request(owner, repo, path, ref)
            if response.status_code == 404:
                return None, await self._repo_visible(owner, repo)
            response.raise_for_status()
            # Raw JSON/JSON5 files can legitimately carry a JSON content type.
            # Detect the Contents API envelope by its structure, not the filename.
            if "json" in response.headers.get("content-type", "").lower():
                with contextlib.suppress(ValueError):
                    payload = response.json()
                    if isinstance(payload, dict) and payload.get("type") == "file" and "encoding" in payload:
                        if payload.get("encoding") != "base64" or not isinstance(payload.get("content"), str):
                            raise RuntimeError(f"Unsupported Contents API encoding for {path}")
                        try:
                            encoded = "".join(payload["content"].split())
                            return base64.b64decode(encoded, validate=True).decode("utf-8-sig"), True
                        except (binascii.Error, UnicodeDecodeError) as exc:
                            raise RuntimeError(f"Invalid encoded Contents API content for {path}") from exc
            return response.content.decode("utf-8-sig"), True
        except (httpx.HTTPError, OSError, ValueError, RuntimeError) as exc:
            logger.warning("Failed to fetch %s from %s/%s@%s: %s", path, owner, repo, ref, exc)
            return None, False

    async def _request(self, owner: str, repo: str, path: str, ref: str | None) -> httpx.Response:
        clean = path.replace("\\", "/").strip("/")
        segments = clean.split("/")
        if not clean or any(segment in {"", ".", ".."} for segment in segments):
            raise ValueError(f"Invalid repository path: {path!r}")
        url = (
            f"{GITHUB_API}/repos/{quote(owner, safe='')}/{quote(repo, safe='')}/contents/"
            + "/".join(quote(segment, safe="") for segment in segments)
        )
        return await self._send(
            url,
            "application/vnd.github.raw+json",
            {"ref": ref} if ref is not None else None,
        )

    async def _repo_visible(self, owner: str, repo: str) -> bool:
        repo_key = (owner.lower(), repo.lower())
        if repo_key in self._visible:
            return self._visible[repo_key]
        if self._offline:
            return False
        url = f"{GITHUB_API}/repos/{quote(owner, safe='')}/{quote(repo, safe='')}"
        try:
            response = await self._send(url, "application/vnd.github+json")
        except (httpx.HTTPError, OSError) as exc:
            logger.warning("Could not check access to %s/%s: %s", owner, repo, exc)
            return False
        if response.status_code == 200:
            self._visible[repo_key] = True
            return True
        if response.status_code == 404:
            logger.warning("Repository %s/%s is missing or not accessible with the current token", owner, repo)
            self._visible[repo_key] = False
        return False
