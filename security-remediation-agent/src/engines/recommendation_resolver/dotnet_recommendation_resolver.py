"""Find stable same-major NuGet candidates without a local checkout.

Registry candidates are not compatibility-tested or security-verified.
Only literal package versions are supported; unresolved MSBuild expressions fail.
"""
import logging
import re
import xml.etree.ElementTree as ET
from pathlib import PurePosixPath

import httpx

from ...utils.manifest_provider import ManifestProvider

logger = logging.getLogger(__name__)
PROJECT_SUFFIXES = {".csproj", ".fsproj", ".vbproj"}
STABLE_VERSION = re.compile(r"^\d+(?:\.\d+){1,3}(?:\+[0-9A-Za-z.-]+)?$")


class NuGetResolutionError(RuntimeError):
    pass


def stable_version_key(value: str) -> tuple[int, int, int, int]:
    """Compare stable numeric NuGet versions, ignoring build metadata."""
    if not STABLE_VERSION.fullmatch(value):
        raise ValueError(f"Unsupported stable NuGet version: {value!r}")
    parts = tuple(int(part) for part in value.split("+", 1)[0].split("."))
    return parts + (0,) * (4 - len(parts))


class DotNetRecommendationResolver:
    def __init__(self, manifest_provider=None, client=None) -> None:
        self._manifest_provider = manifest_provider or ManifestProvider()
        self._client = client

    async def resolve_project_path(self, owner, repo, manifest_path, *, ref=None):
        path = PurePosixPath(manifest_path.replace("\\", "/").strip("/"))
        if path.suffix.lower() in PROJECT_SUFFIXES:
            return path.as_posix()
        entries = await self._manifest_provider.repository_tree(owner, repo, ref)
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
        return await self._manifest_provider.get(owner, repo, str(path), ref)

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

    async def highest_minor_versions(self, owner, repo, project_path, *, ref=None):
        declared = await self._declared_versions(owner, repo, project_path, ref)
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
