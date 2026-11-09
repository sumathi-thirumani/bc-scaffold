"""Populate dependency occurrences and actionable upgrade recommendations."""
import asyncio
import logging
import subprocess
from pathlib import PurePosixPath

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from ..models.security_package_triage import (
    OccurrenceClassification,
    TransistiveOccurances,
    TransistiveSourcePackage,
)
from ..models.security_remediation_constants import SecurityRemediationConstants
from ..models.security_remediation_cache import SecurityRemediationCache
from ..tools.ecosystem_manifest_tool import ManifestTool
from .resolver_factory import RelationshipResolverFactory

logger = logging.getLogger(__name__)
# Ecosystems whose transitive introducers can be resolved from repository files.
TRANSITIVE_RESOLVABLE_ECOSYSTEMS = SecurityRemediationConstants.SUPPORTED_ECOSYSTEMS
class PackageRelationshipResolver:
    """Enrich triage items with resolved versions, roots and introducer paths.

    Core idea: reuse an ecosystem resolver per repository ref and dependency input,
    batch target lookups, then attach each affected occurrence and its parent paths.
    When graph resolution fails, keep the available reported relationship evidence."""
    def __init__(
        self,
        cache: SecurityRemediationCache | None = None,
        manifest_tool: ManifestTool | None = None,
        resolver_factory: RelationshipResolverFactory | None = None,
    ):
        self.manifest_tool = manifest_tool or ManifestTool(cache=cache)
        self.resolver_factory = resolver_factory or RelationshipResolverFactory()
        # Resolvers are cached per repository snapshot/ecosystem/lockfile so a
        # lockfile is fetched and parsed once even when many transitive items
        # share it.
        self._resolvers: dict[tuple, object] = {}
    async def populate(self, owner, repo, items, ref=None):
        """Classify each item as direct/transitive and resolve its introducers.

        Dependabot's relationship is authoritative for declaration status. Raw files
        are passed to ecosystem resolvers only when dependency graph data is needed.
        """
        await self.populate_transitive_introducers(
            owner, repo, items, ref
        )
    async def populate_transitive_introducers(
        self, owner, repo, items, ref=None
    ) -> None:
        """Attach dependency occurrences (introducer paths) to each resolvable item.

        Reuses the ecosystem resolvers under ``engines/resolvers`` so the
        lockfile graph, not Dependabot's reported relationship, is the source of
        truth for who introduces a package.
        """
        pending: list[tuple[object, object, str, str]] = []
        names_by_resolver: dict[int, tuple[object, set[str]]] = {}
        for item in items:
            ecosystem = (item.ecosystem or "").lower()
            if ecosystem not in TRANSITIVE_RESOLVABLE_ECOSYSTEMS:
                logger.info(
                    "Skipping lockfile resolution for %s: ecosystem %s is not supported",
                    item.package,
                    item.ecosystem,
                )
                continue
            path = item.manifest_path
            if not path:
                continue
            lock_path = self.manifest_tool.lockfile_path(ecosystem, path)
            kind = ManifestTool.relationship_resolver_kind(ecosystem, lock_path)
            if not kind:
                logger.debug(
                    "No relationship resolver for %s (%s); keeping reported relationship for %s",
                    lock_path, ecosystem, item.package,
                )
                continue
            resolver_path = "<repository-projects>" if kind == "nuget" else lock_path
            key = (owner.lower(), repo.lower(), ref, kind, resolver_path)
            if key not in self._resolvers:
                self._resolvers[key] = await self._build_resolver(
                    owner, repo, kind, lock_path, ref
                )
            resolver = self._resolvers[key]
            if resolver is None:
                continue
            pending.append((item, resolver, lock_path, kind))
            names_by_resolver.setdefault(id(resolver), (resolver, set()))[1].add(item.package)
        # Batch each resolver's CLI work instead of repeating it per vulnerable package.
        failed: set[int] = set()
        for resolver, names in names_by_resolver.values():
            prefetch = getattr(resolver, "prefetch", None)
            if prefetch is None:
                continue
            try:
                prefetch(sorted(names))
            except (subprocess.SubprocessError, OSError, ValueError) as exc:
                failed.add(id(resolver))
                logger.warning(
                    "Cannot resolve dependency paths for %s; keeping reported relationship: %s",
                    sorted(names), exc,
                )
        for item, resolver, lock_path, kind in pending:
            if id(resolver) in failed:
                continue
            try:
                if kind == "nuget":
                    result = resolver.resolve(item.package, project_path=item.manifest_path)
                else:
                    result = resolver.resolve(item.package)
            except (subprocess.SubprocessError, OSError, ValueError) as exc:
                logger.warning(
                    "Cannot resolve %s from %s; keeping reported relationship: %s",
                    item.package, lock_path, exc,
                )
                continue
            root = self._root_status(resolver, result, item.package)
            if root is not None and kind in {"npm", "pip"}:
                item.istransitive = not root
            self._add_transitive_occurrences(
                item,
                result,
                lock_path,
                vulnerable_range=item.vulnerablility_version_range,
                fixed_version=item.vulnerablility_fixed_version,
                non_root_only=False if kind in {"npm", "pip"} else not item.istransitive,
            )

    @staticmethod
    def _root_status(resolver, result: dict | None, package: str) -> bool | None:
        """``True`` if the lockfile shows ``package`` as a root dependency, ``False`` if it
        is present only under other packages, ``None`` when the lockfile lacks it."""
        if not result:
            return None
        if "occurrences" in result:
            occurrences = result["occurrences"]
            if not occurrences:
                return None
            return any(occurrence.get("is_root") for occurrence in occurrences)
        if not result.get("version"):
            return None
        return any(
            canonicalize_name(introducer.get("package") or "")
            == canonicalize_name(package)
            for introducer in result.get("introducers", [])
        )

    async def _build_resolver(self, owner, repo, kind: str, lock_path: str, ref):
        """Fetch repository inputs and build the ecosystem-specific resolver."""
        try:
            if kind == "nuget":
                entries = await self.manifest_tool.repository_tree(owner, repo, ref)
                project_paths = sorted(
                    entry["path"] for entry in entries
                    if PurePosixPath(entry["path"]).suffix.lower() == ".csproj"
                )
                if not project_paths:
                    raise ValueError("No .csproj files found in repository")
                support_paths = sorted(
                    entry["path"] for entry in entries
                    if (
                        PurePosixPath(entry["path"]).suffix.lower() in {".props", ".targets"}
                        or PurePosixPath(entry["path"]).name.lower()
                        in {"nuget.config", "global.json"}
                    )
                )
                file_paths = project_paths + support_paths
                contents = await asyncio.gather(
                    *(self.manifest_tool.get(owner, repo, path, ref) for path in file_paths)
                )
                project_files = dict(
                    zip(project_paths, contents[:len(project_paths)], strict=True)
                )
                missing_projects = [path for path, text in project_files.items() if not text]
                if missing_projects:
                    raise ValueError(
                        "Cannot load repository project files: " + ", ".join(missing_projects)
                    )
                support_files = {
                    path: text
                    for path, text in zip(
                        support_paths, contents[len(project_paths):], strict=True
                    )
                    if text is not None
                }
                return await self.resolver_factory.create(
                    kind,
                    project_files=project_files,
                    support_files=support_files,
                )

            if kind == "pip":
                requirements_path = await self._pip_requirements_path(
                    owner, repo, lock_path, ref
                )
                requirements_text = await self.manifest_tool.get(
                    owner, repo, requirements_path, ref
                )
                if not requirements_text:
                    return None
                support_files = {}
                try:
                    entries = await self.manifest_tool.repository_tree(owner, repo, ref)
                    support_paths = sorted(
                        entry["path"] for entry in entries
                        if PurePosixPath(entry["path"]).suffix.lower() in {".in", ".txt"}
                        and PurePosixPath(entry["path"]).name.lstrip(".").lower().startswith(
                            ("requirements", "constraints")
                        )
                        and entry["path"] != requirements_path
                    )
                    support_contents = await asyncio.gather(
                        *(self.manifest_tool.get(owner, repo, path, ref) for path in support_paths)
                    )
                    support_files = {
                        path: content
                        for path, content in zip(support_paths, support_contents, strict=True)
                        if content is not None
                    }
                except (OSError, ValueError) as exc:
                    logger.debug("Could not load pip requirement includes: %s", exc)
                return await self.resolver_factory.create(
                    kind,
                    requirements_text,
                    requirements_path=requirements_path,
                    support_files=support_files,
                )

            text = await self.manifest_tool.get(owner, repo, lock_path, ref)
            if not text:
                return None
            if kind in {"npm", "poetry"}:
                companion = "package.json" if kind == "npm" else "pyproject.toml"
                project_path = str(PurePosixPath(lock_path).parent / companion)
                project_text = await self.manifest_tool.get(owner, repo, project_path, ref)
                if not project_text:
                    return None
                return await self.resolver_factory.create(
                    kind,
                    text,
                    project_text=project_text,
                )
            return await self.resolver_factory.create(kind, text)
        except (ValueError, KeyError, TypeError, subprocess.SubprocessError, OSError) as exc:
            logger.warning("Cannot build %s resolver from %s: %s", kind, lock_path, exc)
            return None

    async def _pip_requirements_path(self, owner, repo, manifest_path: str, ref) -> str:
        """Prefer the source manifest for pip's dry run, falling back to compiled pins."""
        path = PurePosixPath(manifest_path.replace("\\", "/"))
        source_paths = []
        if path.suffix.lower() in {".in", ".txt"}:
            source_paths.append(path.with_suffix(".in"))
        source_paths.append(path.parent / "requirements.in")
        for candidate in dict.fromkeys(source_paths):
            if await self.manifest_tool.get(owner, repo, candidate.as_posix(), ref) is not None:
                return candidate.as_posix()
        if path.suffix.lower() == ".txt":
            return path.as_posix()
        fallback = path.parent / "requirements.txt"
        if await self.manifest_tool.get(owner, repo, fallback.as_posix(), ref) is not None:
            return fallback.as_posix()
        raise ValueError(f"No requirements.in or requirements.txt found near {manifest_path}")

    @staticmethod
    def _add_transitive_occurrences(
        item,
        result: dict,
        lock_path: str,
        *,
        vulnerable_range: str | None = None,
        fixed_version: str | None = None,
        non_root_only: bool = False,
    ) -> None:
        """Translate a resolver result into ``TransistiveOccurances`` on ``item``.
        Occurrences covered by any advisory are recorded, so unrelated (already-fixed or
        never-vulnerable) installations of the same package elsewhere in the
        tree don't flood the occurrence list. With ``non_root_only`` (direct items) the
        root install is skipped and only copies pulled in by other packages are kept.
        """
        if not result:
            return
        if "occurrences" in result:
            occurrences = result["occurrences"]
        elif result.get("version"):
            occurrences = [result]
        else:
            occurrences = []
        # A single resolved installation is useful even when it is no longer affected
        # by the advisory. Do not select arbitrarily when several versions are installed.
        if not item.current_version:
            version_occurrences = occurrences
            if not item.istransitive:
                roots = [occurrence for occurrence in occurrences if occurrence.get("is_root")]
                version_occurrences = roots or occurrences
            resolved_versions = {occurrence.get("version") for occurrence in version_occurrences
                                 if occurrence.get("version")}
            if len(resolved_versions) == 1:
                item.current_version = next(iter(resolved_versions))
        if non_root_only:
            # Preserve the installed direct version before excluding root occurrences.
            # Python lockfiles contain one resolved version even when no nested copy exists.
            if not item.current_version and result.get("version"):
                item.current_version = result["version"]
            # Only npm can nest a second copy of a direct package; Python lockfiles
            # hold one version per package, so they contribute nothing here.
            target = canonicalize_name(item.package)
            occurrences = [
                occurrence for occurrence in occurrences
                if occurrence.get("is_root") is False
                and any(
                    canonicalize_name(introducer.get("package") or "") != target
                    for introducer in occurrence.get("introducers", [])
                )
            ]
        # Evaluate each advisory separately so missing/unparseable ranges
        # use their own fixed-version fallback, not another advisory's range.
        advisories = [
            (alert.vulnerable_range, alert.first_patched)
            for alert in item.vulnerabilities
        ] or [(vulnerable_range, fixed_version)]
        for occurrence in occurrences:
            if not any(
                PackageRelationshipResolver._is_vulnerable_occurrence(
                    occurrence.get("version"), affected_range, patched_version,
                )
                for affected_range, patched_version in advisories
            ):
                continue
            introducers = [
                TransistiveSourcePackage(
                    package=introducer["package"],
                    version=introducer.get("version") or "",
                )
                for introducer in occurrence.get("introducers", [])
            ]
            transitive_occurrence = TransistiveOccurances(
                package=item.package,
                version=occurrence.get("version") or "",
                introducers=introducers,
                classification=(
                    OccurrenceClassification.ROOT
                    if occurrence.get("is_root")
                    else OccurrenceClassification.TRANSITIVE
                ),
                manifest_path=occurrence.get("manifest_path") or lock_path,
                paths=PackageRelationshipResolver._dependency_paths(occurrence.get("paths", [])),
            )
            if not occurrence.get("is_root") and not introducers:
                transitive_occurrence.classification = OccurrenceClassification.TRANSITIVE
            if transitive_occurrence not in item.transitive_dependency_occurrences:
                item.transitive_dependency_occurrences.append(transitive_occurrence)
    @staticmethod
    def _dependency_paths(raw_paths) -> list[list[TransistiveSourcePackage]]:
        paths = []
        for raw_path in raw_paths:
            path = []
            for node in raw_path:
                if isinstance(node, dict):
                    name, version = node.get("package"), node.get("version", "")
                elif isinstance(node, str) and "@" in node[1:]:
                    name, version = node.rsplit("@", 1)
                else:
                    break
                if not name:
                    break
                path.append(TransistiveSourcePackage(
                    package=name,
                    version=version,
                ))
            else:
                if path:
                    paths.append(path)
        return paths

    @staticmethod
    def _is_vulnerable_occurrence(
        installed_version: str | None,
        vulnerable_range: str | None,
        fixed_version: str | None,
    ) -> bool:
        """Keep only occurrences covered by the alert's vulnerable range.
        GitHub ranges can contain comma-separated AND constraints and ``||``
        alternatives. If the range cannot be parsed, fall back to the fixed
        version. On an unrecognised version, retain the occurrence so a
        vulnerable path is never silently hidden.
        """
        if not installed_version:
            return True
        try:
            installed = Version(installed_version)
        except InvalidVersion:
            return True
        if vulnerable_range:
            try:
                return any(
                    SpecifierSet(part.strip()).contains(installed, prereleases=True)
                    for part in vulnerable_range.split("||")
                    if part.strip()
                )
            except InvalidSpecifier:
                pass
        if not fixed_version:
            return True
        try:
            return installed < Version(fixed_version)
        except InvalidVersion:
            return True
