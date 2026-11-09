"""Find stable same-major NuGet candidates without a local checkout.

Registry candidates are not compatibility-tested or security-verified.
Only literal package versions are supported; unresolved MSBuild expressions fail.
"""
import asyncio
import logging
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import PurePosixPath

import httpx
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from ....tools.ecosystem_manifest_tool import ManifestTool

logger = logging.getLogger(__name__)
PROJECT_SUFFIXES = {".csproj", ".fsproj", ".vbproj"}
STABLE_VERSION = re.compile(r"^\d+(?:\.\d+){1,3}(?:\+[0-9A-Za-z.-]+)?$")
NUGET_REGISTRATION_URL = "https://api.nuget.org/v3/registration5-gz-semver2/{name}/index.json"
PACKAGE_ID = re.compile(r"[a-z0-9_.-]+")
MAX_CONCURRENT_REQUESTS = 10
MAX_ATTEMPTS = 3
RETRYABLE_STATUS = {429, 500, 502, 503, 504}
MAX_EXPANSIONS = 500
MAX_DEPTH = 64


class NuGetResolutionError(RuntimeError):
    """NuGet project selection, declaration parsing or registry inference failed."""
    pass


def stable_version_key(value: str) -> tuple[int, int, int, int]:
    """Compare stable numeric NuGet versions, ignoring build metadata."""
    if not STABLE_VERSION.fullmatch(value):
        raise ValueError(f"Unsupported stable NuGet version: {value!r}")
    parts = tuple(int(part) for part in value.split("+", 1)[0].split("."))
    return parts + (0,) * (4 - len(parts))


class DotNetRecommendationResolver:
    """Find stable same-major NuGet candidates from repository declarations.

    Core idea: identify one project, combine literal inline and central package
    versions, and query registry releases. These suggestions do not prove that
    the project restores; verification is a separate pipeline step."""
    def __init__(self, manifest_tool=None, client=None) -> None:
        self._manifest_tool = manifest_tool or ManifestTool()
        self._client = client

    async def resolve_project_path(self, owner, repo, manifest_path, *, ref=None):
        path = PurePosixPath(manifest_path.replace("\\", "/").strip("/"))
        if path.suffix.lower() in PROJECT_SUFFIXES:
            return path.as_posix()
        try:
            entries = await self._manifest_tool.repository_tree(owner, repo, ref)
        except (ValueError, httpx.HTTPError) as exc:
            raise NuGetResolutionError(f"Cannot list repository files: {exc}") from exc
        projects = [PurePosixPath(e["path"]) for e in entries
                    if PurePosixPath(e["path"]).suffix.lower() in PROJECT_SUFFIXES]
        same = [p for p in projects if p.parent == path.parent]
        stem = [p for p in same if p.stem.casefold() == path.stem.casefold()]
        candidates = stem or same
        if len(candidates) == 1:
            return candidates[0].as_posix()
        raise NuGetResolutionError(
            f"Cannot identify one project for {manifest_path}; "
            "solution-wide and shared manifests require explicit project selection"
        )

    async def _text(self, owner, repo, path, ref):
        return await self._manifest_tool.get(owner, repo, str(path), ref)

    @staticmethod
    def _parse(text, path):
        try:
            return ET.fromstring(text)
        except ET.ParseError as exc:
            raise NuGetResolutionError(f"Invalid XML in {path}: {exc}") from exc

    async def _declared_versions(self, owner, repo, project_path, ref):
        text = await self._text(owner, repo, project_path, ref)
        if text is None:
            raise NuGetResolutionError(f"Cannot fetch {project_path}")
        root = self._parse(text, project_path)
        central = {}
        # MSBuild normally discovers the nearest Directory.Packages.props.
        for parent in PurePosixPath(project_path).parents:
            props_path = parent / "Directory.Packages.props"
            props = await self._text(owner, repo, props_path, ref)
            if props is not None:
                props_root = self._parse(props, props_path)
                for node in props_root.iter():
                    if node.tag.rsplit("}", 1)[-1] == "PackageVersion":
                        name = node.get("Include") or node.get("Update")
                        version = node.get("Version")
                        if name and version:
                            central.setdefault(name.casefold(), set()).add(version)
                break
        versions = {}
        for node in root.iter():
            if node.tag.rsplit("}", 1)[-1] != "PackageReference":
                continue
            name = node.get("Include")
            if not name:
                continue
            children = {c.tag.rsplit("}", 1)[-1]: (c.text or "").strip() for c in node}
            value = (node.get("VersionOverride") or children.get("VersionOverride")
                     or node.get("Version") or children.get("Version"))
            choices = {value} if value else central.get(name.casefold(), set())
            if len(choices) != 1:
                raise NuGetResolutionError(f"Ambiguous or missing version for {name}")
            value = next(iter(choices))
            try:
                stable_version_key(value)
            except ValueError as exc:
                raise NuGetResolutionError(
                    f"{name}: {value!r} needs MSBuild/range/prerelease resolution"
                ) from exc
            previous = versions.get(name.casefold())
            if previous is not None and previous != value:
                raise NuGetResolutionError(f"Multiple versions for {name}; resolve per framework")
            versions[name.casefold()] = value
        return versions

    async def highest_same_major_versions(self, owner, repo, project_path, *, ref=None, package_names=None):
        """Return the highest newer stable release within each declared package's major."""
        declared = await self._declared_versions(owner, repo, project_path, ref)
        if package_names is not None:
            requested = {name.casefold() for name in package_names}
            declared = {name: version for name, version in declared.items() if name in requested}
        if self._client is not None:
            return await self._recommend(self._client, declared)
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
            return await self._recommend(client, declared)

    async def _recommend(self, client, declared):
        result = {}
        for name, requested in declared.items():
            if not re.fullmatch(r"[a-z0-9_.-]+", name):
                raise NuGetResolutionError(f"Invalid package ID: {name}")
            try:
                response = await client.get(
                    f"https://api.nuget.org/v3-flatcontainer/{name}/index.json"
                )
                response.raise_for_status()
                versions = response.json()["versions"]
                if not isinstance(versions, list) or not all(isinstance(v, str) for v in versions):
                    raise ValueError("Invalid versions response")
            except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
                raise NuGetResolutionError(f"NuGet lookup failed for {name}: {exc}") from exc
            current = stable_version_key(requested)
            candidates = [v for v in versions if STABLE_VERSION.fullmatch(v)
                          and stable_version_key(v)[0] == current[0]
                          and stable_version_key(v) > current]
            result[f"{name}:requested"] = requested
            if candidates:
                result[f"{name}:candidate"] = max(candidates, key=stable_version_key)
        return result


def _stable(raw) -> Version | None:
    """Parse a stable NuGet version, ignoring build metadata; None otherwise."""
    if not isinstance(raw, str):
        return None
    try:
        version = Version(raw.split("+", 1)[0])
    except InvalidVersion:
        return None
    return None if version.is_prerelease or version.is_devrelease else version


def parse_nuget_range(text) -> tuple[Version | None, bool, Version | None, bool] | None:
    """Parse a NuGet version range into (lower, lower_inclusive, upper, upper_inclusive).

    Returns None for unsupported syntax such as floating versions or prereleases.
    """
    if not isinstance(text, str) or not text.strip():
        return None
    text = text.strip()
    if text[0] not in "[(":
        minimum = _stable(text)
        return (minimum, True, None, False) if minimum else None
    if text[-1] not in "])":
        return None
    inner = text[1:-1]
    low_inclusive, high_inclusive = text[0] == "[", text[-1] == "]"
    if "," not in inner:
        exact = _stable(inner.strip())
        return (exact, True, exact, True) if exact and low_inclusive and high_inclusive else None
    low_text, high_text = (part.strip() for part in inner.split(",", 1))
    low, high = _stable(low_text) if low_text else None, _stable(high_text) if high_text else None
    if (low_text and low is None) or (high_text and high is None):
        return None
    if low is None and high is None:
        return None
    return low, low_inclusive, high, high_inclusive


def _in_range(version: Version, parsed) -> bool:
    low, low_inclusive, high, high_inclusive = parsed
    if low is not None and (version < low or (version == low and not low_inclusive)):
        return False
    if high is not None and (version > high or (version == high and not high_inclusive)):
        return False
    return True


@dataclass(frozen=True)
class NuGetRelease:
    """Represent a NuGet release and its dependency evidence for registry inference."""
    version: Version
    raw: str
    # Dependency id (casefolded) -> ranges declared across all target frameworks.
    dependencies: dict[str, list[str]] = field(default_factory=dict)


class NuGetRegistryClient:
    """Read NuGet registration metadata and shortlist parent upgrade candidates."""

    def __init__(self, client: httpx.AsyncClient | None = None, *, retry_delay: float = 0.5):
        self._client = client
        self._retry_delay = retry_delay
        self._tasks: dict[str, asyncio.Task] = {}
        self._semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)

    async def get(self, package: str) -> list[NuGetRelease]:
        """Return listed, non-deprecated stable releases; reuse completed or pending requests."""
        key = package.casefold()
        task = self._tasks.get(key)
        if task is None:
            task = asyncio.ensure_future(self._load(key))
            self._tasks[key] = task
        try:
            return await asyncio.shield(task)
        except Exception:
            if self._tasks.get(key) is task and task.done():
                self._tasks.pop(key, None)
            raise

    async def get_many(self, packages) -> dict[str, list[NuGetRelease]]:
        unique = list(dict.fromkeys(name.casefold() for name in packages))
        return dict(zip(unique, await asyncio.gather(*(self.get(name) for name in unique))))

    async def _load(self, name: str) -> list[NuGetRelease]:
        if not PACKAGE_ID.fullmatch(name):
            raise NuGetResolutionError(f"Invalid package ID: {name}")
        try:
            index = await self._get_json(NUGET_REGISTRATION_URL.format(name=name))
            pages = index["items"]
            pages = await asyncio.gather(*(
                self._get_json(page["@id"]) if "items" not in page else _done(page)
                for page in pages
            ))
            return self._releases(leaf for page in pages for leaf in page["items"])
        except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
            raise NuGetResolutionError(f"NuGet lookup failed for {name}: {exc}") from exc

    @staticmethod
    def _releases(leaves) -> list[NuGetRelease]:
        releases = []
        for leaf in leaves:
            entry = leaf.get("catalogEntry") if isinstance(leaf, dict) else None
            if not isinstance(entry, dict) or entry.get("listed") is False or entry.get("deprecation"):
                continue
            version = _stable(entry.get("version"))
            if version is None:
                continue
            dependencies: dict[str, list[str]] = {}
            for group in entry.get("dependencyGroups") or []:
                for dependency in group.get("dependencies") or []:
                    dependencies.setdefault(str(dependency.get("id", "")).casefold(), []).append(
                        dependency.get("range") or ""
                    )
            releases.append(NuGetRelease(version, entry["version"], dependencies))
        return sorted(releases, key=lambda release: release.version)

    async def _get_json(self, url: str):
        for attempt in range(MAX_ATTEMPTS):
            last = attempt == MAX_ATTEMPTS - 1
            try:
                async with self._semaphore:
                    if self._client is not None:
                        response = await self._client.get(url)
                    else:
                        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
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
        if not isinstance(data, dict):
            raise ValueError(f"Unexpected NuGet metadata from {url}")
        return data

    async def select_candidates(
        self,
        parent: str,
        child: str,
        vulnerable_range: str | None,
        fixed_version: str | None,
        current_parent_version: str | None,
        *,
        dependency_paths: list[list[dict[str, str]]] | None = None,
    ) -> list[str]:
        """List newer same-major parent versions whose declared dependencies avoid the advisory.

        Walk only the known vulnerable paths. NuGet picks the lowest version that
        satisfies a range, so each edge resolves to the lowest matching release;
        a range declared in any target framework must be safe. Unsupported ranges,
        cycles, missing paths and traversal limits fail closed. Raises
        NuGetResolutionError when registry metadata cannot be loaded.
        """
        current = _stable(current_parent_version)
        if current is None:
            return []
        paths = dependency_paths or [[{"package": parent}, {"package": child}]]
        if any(
            len(path) < 2
            or str(path[0].get("package", "")).casefold() != parent.casefold()
            or str(path[-1].get("package", "")).casefold() != child.casefold()
            for path in paths
        ):
            return []
        edges: dict[str, set[str]] = {}
        for path in paths:
            for left, right in zip(path, path[1:]):
                edges.setdefault(left["package"].casefold(), set()).add(right["package"].casefold())
        names = set(edges) | {name for targets in edges.values() for name in targets}
        metadata = await self.get_many(names)

        def safe_target(version: Version) -> bool:
            try:
                if vulnerable_range:
                    return not any(
                        SpecifierSet(part.strip()).contains(version, prereleases=True)
                        for part in vulnerable_range.split("||") if part.strip()
                    )
                return bool(fixed_version) and version >= Version(fixed_version)
            except (InvalidVersion, InvalidSpecifier):
                return False

        child_key = child.casefold()
        checked: dict[tuple[str, str], bool] = {}
        expansions = 0

        def safe(name: str, release: NuGetRelease, ancestors: frozenset) -> bool:
            nonlocal expansions
            if name == child_key:
                return safe_target(release.version)
            key = (name, release.raw)
            if key in checked:
                return checked[key]
            if key in ancestors:
                return False
            expansions += 1
            if expansions > MAX_EXPANSIONS or len(ancestors) >= MAX_DEPTH:
                return False
            result = True
            for dependency in edges.get(name, ()):
                for text in release.dependencies.get(dependency, ()):
                    parsed = parse_nuget_range(text)
                    options = [
                        entry for entry in metadata.get(dependency, ())
                        if parsed and _in_range(entry.version, parsed)
                    ]
                    if not options or not safe(dependency, options[0], ancestors | {key}):
                        result = False
                        break
                if not result:
                    break
            checked[key] = result
            return result

        parent_key = parent.casefold()
        candidates = []
        for release in metadata.get(parent_key, ()):
            if release.version <= current or release.version.major != current.major:
                continue
            expansions = 0
            if safe(parent_key, release, frozenset()):
                candidates.append(release.raw)
        return candidates


async def _done(value):
    return value
