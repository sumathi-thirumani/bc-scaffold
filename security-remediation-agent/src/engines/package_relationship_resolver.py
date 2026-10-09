"""Populate dependency occurrences and actionable upgrade recommendations."""
import asyncio
import logging
import subprocess
from pathlib import PurePosixPath
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version
from ..models.security_package_triage import (
    TransistiveOccurances,
    TransistiveSourcePackage,
)
from ..models.security_remediation_constants import SecurityRemediationConstants
from ..models.security_remediation_context import SecurityRemediationCache
from ..utils.manifest_provider import ManifestProvider
from .recommendation_resolver.dotnet_recommendation_resolver import (
    DotNetRecommendationResolver,
    NuGetResolutionError,
)
from .resolver_factory import RelationshipResolverFactory
logger = logging.getLogger(__name__)
# Ecosystems supported by manifest relationship resolution.
SUPPORTED_ECOSYSTEMS = SecurityRemediationConstants.SUPPORTED_ECOSYSTEMS
# Ecosystems whose transitive introducers can be resolved from a lockfile.
TRANSITIVE_RESOLVABLE_ECOSYSTEMS = frozenset(
    SecurityRemediationConstants.SUPPORTED_ECOSYSTEMS - {"nuget"}
)
NUGET_ECOSYSTEMS = frozenset({"nuget"})
class PackageRelationshipResolver:
    def __init__(
        self,
        cache: SecurityRemediationCache | None = None,
        manifest_provider: ManifestProvider | None = None,
        resolver_factory: RelationshipResolverFactory | None = None,
    ):
        self.manifest_provider = manifest_provider or ManifestProvider(cache=cache)
        self.resolver_factory = resolver_factory or RelationshipResolverFactory()
        # Resolvers are cached per repository snapshot/ecosystem/lockfile so a
        # lockfile is fetched and parsed once even when many transitive items
        # share it.
        self._resolvers: dict[tuple, object] = {}
    def _manifests_to_cache(self, items) -> dict[tuple[str, str], str]:
        """Map each unique ecosystem/path pair to its manifest path."""
        manifests: dict[tuple[str, str], str] = {}
        for item in items:
            ecosystem = (item.ecosystem or "").lower()
            for alert in item.vulnerabilities:
                path = alert.manifest_path
                if ecosystem == "nuget":
                    continue
                if (
                    ecosystem in {"pip", "pypi"}
                    and PurePosixPath(path).name == "requirements.txt"
                ):
                    path = str(PurePosixPath(path).parent / "requirements.in")
                if ecosystem in SUPPORTED_ECOSYSTEMS and path:
                    if (
                        ecosystem in {"npm", "npm_and_yarn"}
                        and self.manifest_provider.is_lockfile(path)
                    ):
                        path = str(PurePosixPath(path).parent / "package.json")
                    manifests.setdefault((ecosystem, path), path)
        return manifests
    async def cache_manifest(self, owner, repo, items, ref=None) -> None:
        """Fetch and cache every unique manifest path reported by ``items``.
        Each manifest is fetched and parsed once per repository snapshot, so later
        lookups are served from the run cache. A package declared in one of its own
        manifests is a direct dependency, so ``istransitive`` is cleared for it
        regardless of what the alert claimed.
        """
        manifests = self._manifests_to_cache(items)
        if not manifests:
            logger.info("No manifests to cache for %s/%s", owner, repo)
            return
        keys = sorted(manifests)
        logger.info(
            "Caching %d manifest(s) for %s/%s: %s",
            len(keys),
            owner,
            repo,
            ", ".join(manifests[key] for key in keys),
        )
        await asyncio.gather(
            *(
                self.manifest_provider.declared_packages(
                    owner, repo, manifests[key], ref, ecosystem=key[0]
                )
                for key in keys
            )
        )
    async def populate(self, owner, repo, items, ref=None):
        await self.cache_manifest(owner, repo, items, ref)
        nuget_resolver = DotNetRecommendationResolver(
            manifest_provider=self.manifest_provider,
        )
        nuget_recommendations: dict[str, dict[str, str]] = {}
        for item in items:
            ecosystem = (item.ecosystem or "").lower()
            if ecosystem not in SUPPORTED_ECOSYSTEMS:
                logger.info(
                    "Skipping %s: ecosystem %s is not supported", item.package, item.ecosystem
                )
                continue
            if ecosystem in NUGET_ECOSYSTEMS:
                project_path = item.manifest_path or ""
                if project_path and not item.current_version:
                    try:
                        resolved_path = await nuget_resolver.resolve_project_path(
                            owner, repo, project_path, ref=ref,
                        )
                        if resolved_path:
                            if resolved_path not in nuget_recommendations:
                                nuget_recommendations[resolved_path] = (
                                    await nuget_resolver.highest_minor_versions(
                                        owner=owner,
                                        repo=repo,
                                        project_path=resolved_path,
                                        ref=ref,
                                    )
                                )
                            item.current_version = nuget_recommendations[resolved_path].get(
                                f"{item.package.casefold()}:requested", "",
                            )
                    except NuGetResolutionError as exc:
                        logger.warning(
                            "NuGet lookup failed for %s in %s: %s",
                            item.package, project_path, exc,
                        )
                    logger.info(
                        "NuGet declared version for %s: %s (not restore-verified)",
                        item.package, item.current_version or "(unresolved)",
                    )
                continue
            package = self.manifest_provider.normalize(item.package, ecosystem)
            path = item.manifest_path
            if ecosystem in {"pip", "pypi"} and PurePosixPath(path).name == "requirements.txt":
                path = str(PurePosixPath(path).parent / "requirements.in")
            if ecosystem in {"npm", "npm_and_yarn"} and self.manifest_provider.is_lockfile(path):
                path = str(PurePosixPath(path).parent / "package.json")
            cache_key = self.manifest_provider.cache.manifest_cache.key(owner, repo, path, ref)
            cached = self.manifest_provider.cache.manifest_cache.get_packages(cache_key) or {}
            if path and ecosystem not in cached:
                logger.warning(
                    "Manifest %s unavailable; keeping reported relationship for %s",
                    path,
                    item.package,
                )
                continue
            declared = cached.get(ecosystem, {})
            if package in declared:
                item.istransitive = False
                if declared[package] and not item.current_version:
                    item.current_version = declared[package]
            else:
                item.istransitive = True
        await self.populate_transitive_introducers(owner, repo, items, ref)
    async def populate_transitive_introducers(self, owner, repo, items, ref=None) -> None:
        """Resolve actionable root introducers for every item still marked transitive.
        Reuses the resolvers under ``relationship_resolver`` (npm/pip/poetry) so the
        lockfile graph, not Dependabot's reported relationship, is the source of
        truth for who introduces a transitive package.
        """
        for item in items:
            ecosystem = (item.ecosystem or "").lower()
            if not item.istransitive:
                continue
            if ecosystem not in TRANSITIVE_RESOLVABLE_ECOSYSTEMS or ecosystem in NUGET_ECOSYSTEMS:
                logger.info(
                    "Skipping transitive resolution for %s: ecosystem %s is not supported",
                    item.package,
                    item.ecosystem,
                )
                continue
            path = item.manifest_path
            if not path:
                continue
            is_poetry = ecosystem == "poetry"
            is_python = is_poetry or ecosystem in {"pip", "pypi"}
            if is_poetry:
                lock_path = str(PurePosixPath(path).parent / "poetry.lock")
            elif is_python:
                lock_path = path
            elif self.manifest_provider.is_lockfile(path):
                lock_path = path
            else:
                lock_path = str(PurePosixPath(path).parent / "package-lock.json")
            key = (owner.lower(), repo.lower(), ref, ecosystem, lock_path)
            if key not in self._resolvers:
                self._resolvers[key] = await self._build_resolver(
                    owner, repo, ecosystem, lock_path, ref, is_poetry=is_poetry
                )
            resolver = self._resolvers[key]
            if resolver is None:
                continue
            result = resolver.resolve(item.package)
            self._add_transitive_occurrences(
                item,
                result,
                lock_path,
                vulnerable_range=item.vulnerablility_version_range,
                fixed_version=item.vulnerablility_fixed_version,
            )
    async def _build_resolver(
        self, owner, repo, ecosystem: str, lock_path: str, ref, *, is_poetry: bool
    ):
        """Fetch the lockfile (and companion manifest for poetry) and build a resolver."""
        try:
            text = await self.manifest_provider.get(owner, repo, lock_path, ref)
            if not text:
                return None
            if is_poetry:
                project_path = str(PurePosixPath(lock_path).parent / "pyproject.toml")
                project_text = await self.manifest_provider.get(owner, repo, project_path, ref)
                if not project_text:
                    return None
                return await self.resolver_factory.create(
                    ecosystem,
                    text,
                    project_text=project_text,
                )
            return await self.resolver_factory.create(ecosystem, text)
        except (ValueError, KeyError, TypeError, subprocess.SubprocessError, OSError) as exc:
            logger.warning("Cannot build resolver for %s from %s: %s", ecosystem, lock_path, exc)
            return None
    @staticmethod
    def _add_transitive_occurrences(
        item,
        result: dict,
        lock_path: str,
        *,
        vulnerable_range: str | None = None,
        fixed_version: str | None = None,
    ) -> None:
        """Translate a resolver result into ``TransistiveOccurances`` on ``item``.
        Only occurrences whose installed version falls inside the alert's
        vulnerable range are recorded, so unrelated (already-fixed or
        never-vulnerable) installations of the same package elsewhere in the
        tree don't flood the occurrence list.
        """
        if not result:
            return
        if "occurrences" in result:
            occurrences = result["occurrences"]
        elif result.get("version"):
            occurrences = [result]
        else:
            occurrences = []
        for occurrence in occurrences:
            if not PackageRelationshipResolver._is_vulnerable_occurrence(
                occurrence.get("version"), vulnerable_range, fixed_version
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
                manifest_path=lock_path,
            )
            if transitive_occurrence not in item.transitive_dependency_occurrences:
                item.transitive_dependency_occurrences.append(transitive_occurrence)
            if occurrence.get("version") and not item.current_version:
                item.current_version = occurrence["version"]
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
