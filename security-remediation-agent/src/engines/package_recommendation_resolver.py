"""Resolve actionable package upgrade recommendations."""

import logging
from collections.abc import Mapping

from packaging.version import InvalidVersion, Version

from ..models.gh.pull_request_metadata import PullRequestMetadata
from ..models.security_package_triage import (
    PackageUpgradeRecommendation,
    SecurityPackageTriage,
    TransistiveSourcePackage,
)
from .resolvers.recommendation_resolver.dotnet_recommendation_resolver import NuGetResolutionError
from .resolvers.recommendation_resolver.npm_recommendation_resolver import (
    NpmParentVersionResolver,
)
from .resolvers.recommendation_resolver.pip_recommendation_resolver import (
    PipParentVersionResolver,
)
from .resolvers.recommendation_resolver_factory import (
    NuGetParentVersionResolver,
    RecommendationResolverFactory,
)

logger = logging.getLogger(__name__)


class PackageRecommendationResolver:
    """Attach actionable direct or parent upgrade candidates to a triaged package.

    Core idea: match direct findings to sufficient bot PRs; for transitive findings,
    ask the ecosystem resolver which introducing parent releases avoid the affected
    child versions. Preserve candidate evidence for later review and verification."""
    def __init__(
        self,
        resolver_factory: RecommendationResolverFactory | None = None,
    ) -> None:
        self.resolver_factory = resolver_factory or RecommendationResolverFactory()

    async def populate_remediation_version(
        self,
        triage: SecurityPackageTriage,
        pull_requests_by_package: Mapping[str, list[PullRequestMetadata]] | None = None,
        *,
        owner: str | None = None,
        repo: str | None = None,
        ref: str | None = None,
    ) -> None:
        """Populate direct PR or transitive parent upgrade recommendations."""
        if not triage.istransitive:
            self._populate_direct_recommendations(triage, pull_requests_by_package)
            if not triage.package_upgrade_recommendations:
                await self._populate_registry_recommendation(triage)
            return

        try:
            Version(triage.vulnerablility_fixed_version)
        except InvalidVersion:
            logger.warning(
                "Cannot resolve transitive remediation for %s without a valid fixed version: %r",
                triage.package,
                triage.vulnerablility_fixed_version,
            )
            triage.package_upgrade_recommendations = []
            triage.is_pull_available = False
            triage.pull_request_metadata = []
            return

        if not owner or not repo or not triage.manifest_path:
            logger.warning(
                "Cannot resolve transitive remediation for %s without repository context",
                triage.package,
            )
            return

        try:
            version_resolver = await self.resolver_factory.load(
                triage.ecosystem,
                owner,
                repo,
                triage.manifest_path,
                ref=ref,
            )
        except (OSError, ValueError, NuGetResolutionError) as exc:
            logger.warning(
                "Cannot load recommendation resolver for %s: %s",
                triage.package,
                exc,
            )
            return

        recommendations = []
        parents = {}
        paths_by_parent = {}
        for occurrence in triage.transitive_dependency_occurrences:
            for introducer in occurrence.introducers:
                key = (introducer.package, introducer.version)
                parents[key] = introducer
                paths = paths_by_parent.setdefault(key, [])
                for path in occurrence.paths:
                    if path and (path[0].package, path[0].version) == key:
                        rendered = [{"package": node.package, "version": node.version} for node in path]
                        if rendered not in paths:
                            paths.append(rendered)
        for (parent, current), introducer in parents.items():
            recommendation = await self._resolve_parent_recommendation(
                triage,
                parent,
                current,
                version_resolver,
                dependency_paths=paths_by_parent[(parent, current)],
                introducer=introducer,
            )
            if recommendation is not None:
                recommendations.append(recommendation)

        triage.package_upgrade_recommendations = recommendations
        triage.is_pull_available = False
        triage.pull_request_metadata = []

    async def _populate_registry_recommendation(self, triage: SecurityPackageTriage) -> None:
        """Give a direct package without a bot PR registry-based candidates, like a parent has.

        The required fix is the highest patched version within the current major when
        advisories provide one, so a package on 0.x is not forced to a 1.x-only fix."""
        try:
            current = Version(triage.current_version)
            fixed = Version(triage.vulnerablility_fixed_version)
        except InvalidVersion:
            return
        same_major = []
        for alert in triage.vulnerabilities:
            try:
                patched = Version(alert.first_patched)
            except InvalidVersion:
                continue
            if patched.major == current.major:
                same_major.append(patched)
        required = max(same_major) if same_major else fixed
        try:
            versions = await self._registry_versions(triage.ecosystem, triage.package)
        except Exception as exc:
            logger.warning("Cannot list registry versions for %s: %s", triage.package, exc)
            return
        candidates = []
        for raw in versions:
            try:
                if Version(raw) >= required:
                    candidates.append(raw)
            except InvalidVersion:
                continue
        if candidates:
            triage.package_upgrade_recommendations = [PackageUpgradeRecommendation(
                package=triage.package, from_version=triage.current_version,
                qualifying_upgrade_versions=candidates, requires_verification=True, source="registry",
            )]

    async def _registry_versions(self, ecosystem: str, package: str) -> list[str]:
        factory = self.resolver_factory
        kind = ecosystem.lower()
        if kind in {"npm", "npm_and_yarn"}:
            data = await factory.npm_metadata.get(package)
            return [version for version, manifest in (data.get("versions") or {}).items()
                    if not (isinstance(manifest, dict) and manifest.get("deprecated"))]
        if kind in {"pip", "pypi", "poetry"}:
            return await factory.pypi_metadata.list_versions_descending(package)
        if kind == "nuget":
            return [release.raw for release in await factory.nuget_metadata.get(package)]
        return []

    def _populate_direct_recommendations(
        self,
        triage: SecurityPackageTriage,
        pull_requests_by_package: Mapping[str, list[PullRequestMetadata]] | None,
    ) -> None:
        package_pull_requests = (
            pull_requests_by_package.get(triage.package.lower(), [])
            if pull_requests_by_package
            else []
        )
        matched_pull_requests = self.filter_remediation_pull_requests(
            triage,
            package_pull_requests,
        )
        triage.is_pull_available = bool(matched_pull_requests)
        triage.pull_request_metadata = matched_pull_requests
        triage.package_upgrade_recommendations = [
            PackageUpgradeRecommendation(
                package=version_bump.package,
                from_version=version_bump.from_version,
                qualifying_upgrade_versions=[version_bump.to_version],
                source="dependabot_pr",
                pr_number=pull_request.pr_number,
                pull_url=pull_request.pull_url,
                pr_branch=pull_request.pr_branch,
            )
            for pull_request in matched_pull_requests
            for version_bump in pull_request.version_bumps
            if version_bump.package.casefold() == triage.package.casefold()
        ]

    @staticmethod
    async def _resolve_parent_recommendation(
        triage: SecurityPackageTriage,
        parent: str,
        current_parent_version: str,
        version_resolver: (
            NpmParentVersionResolver | PipParentVersionResolver | NuGetParentVersionResolver
        ),
        *,
        dependency_paths: list[list[dict[str, str]]] | None = None,
        introducer: TransistiveSourcePackage | None = None,
    ) -> PackageUpgradeRecommendation | None:
        if isinstance(version_resolver, NuGetParentVersionResolver):
            resolution = await version_resolver.resolve(
                parent,
                triage.package,
                triage.vulnerablility_fixed_version,
                current_parent_version=current_parent_version,
                dependency_paths=dependency_paths,
                vulnerable_range=triage.vulnerablility_version_range,
            )
            source = resolution.source
        elif isinstance(version_resolver, NpmParentVersionResolver):
            resolution = await version_resolver.resolve(
                parent,
                triage.package,
                triage.vulnerablility_version_range,
                current_parent_version=current_parent_version,
                fixed_version=triage.vulnerablility_fixed_version,
                dependency_paths=dependency_paths,
            )
            source = resolution.source or "npm_registry"
        else:
            resolution = await version_resolver.resolve(
                parent,
                triage.package,
                triage.vulnerablility_fixed_version,
                current_parent_version=current_parent_version,
                dependency_paths=dependency_paths,
                vulnerable_range=triage.vulnerablility_version_range,
            )
            source = resolution.source

        action = getattr(resolution, "action", "upgrade_parent")
        if introducer is not None:
            introducer.recommendation_action = action
            introducer.recommended_version = resolution.resolved_version
            introducer.requires_verification = getattr(resolution, "requires_verification", False)
        if not resolution.resolved or not resolution.resolved_version:
            reason = getattr(resolution, "reason", "") or "No parent upgrade candidate was identified"
            note = f"{parent} {current_parent_version or 'unknown'} ({action}): {reason}"
            if note not in triage.notes.splitlines():
                triage.notes = "\n".join(part for part in (triage.notes, note) if part)
            logger.info(
                "No upgrade recommended for %s %s (%s): %s",
                parent, current_parent_version, action, reason,
            )
            return None
        return PackageUpgradeRecommendation(
            package=parent,
            from_version=current_parent_version,
            qualifying_upgrade_versions=list(resolution.qualifying_upgrade_versions),
            requires_verification=getattr(resolution, "requires_verification", False),
            source=source,
        )

    def filter_remediation_pull_requests(
        self,
        triage: SecurityPackageTriage,
        pull_requests: list[PullRequestMetadata],
    ) -> list[PullRequestMetadata]:
        """Return PRs that upgrade the package to its fixed version or newer."""
        try:
            fixed_version = Version(triage.vulnerablility_fixed_version)
        except InvalidVersion:
            logger.warning(
                "Cannot compare invalid fixed version %r for package %s",
                triage.vulnerablility_fixed_version,
                triage.package,
            )
            return []

        package = triage.package.casefold()
        matching_pull_requests = []
        for pull_request in pull_requests:
            for version_bump in pull_request.version_bumps:
                if version_bump.package.casefold() != package:
                    continue

                try:
                    pull_request_version = Version(version_bump.to_version)
                except InvalidVersion:
                    logger.warning(
                        "Skipping invalid PR version %r for package %s in PR #%s",
                        version_bump.to_version,
                        triage.package,
                        pull_request.pr_number,
                    )
                    continue

                if pull_request_version >= fixed_version:
                    matching_pull_requests.append(pull_request)
                    break

        return matching_pull_requests
