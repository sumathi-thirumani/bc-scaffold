"""Resolve actionable package upgrade recommendations."""

import logging
from collections.abc import Mapping

from packaging.version import InvalidVersion, Version

from ..models.gh.pull_request_metadata import PullRequestMetadata
from ..models.security_package_triage import (
    PackageUpgradeRecommendation,
    SecurityPackageTriage,
)
from .recommendation_resolver.pip_parent_version_resolver import (
    PipParentVersionResolver,
)
from .resolver_factory import RecommendationResolverFactory
from .version_resolver.npm_parent_version_resolver import NpmParentVersionResolver

logger = logging.getLogger(__name__)


class PackageRecommendationResolver:
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
        except (OSError, ValueError) as exc:
            logger.warning(
                "Cannot load recommendation resolver for %s: %s",
                triage.package,
                exc,
            )
            return

        recommendations = []
        for occurrence in triage.transitive_dependency_occurrences:
            for introducer in occurrence.introducers:
                recommendation = await self._resolve_parent_recommendation(
                    triage,
                    introducer.package,
                    introducer.version,
                    version_resolver,
                )
                if recommendation is not None:
                    recommendations.append(recommendation)

        triage.package_upgrade_recommendations = recommendations
        triage.is_pull_available = False
        triage.pull_request_metadata = []

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
                to_version=version_bump.to_version,
                minimum_upgradable_version=self._non_breaking_version(
                    version_bump.from_version,
                    version_bump.to_version,
                ),
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
        version_resolver: NpmParentVersionResolver | PipParentVersionResolver,
    ) -> PackageUpgradeRecommendation | None:
        if isinstance(version_resolver, NpmParentVersionResolver):
            resolution = await version_resolver.resolve(
                parent,
                triage.package,
                triage.vulnerablility_version_range,
                current_parent_version=current_parent_version,
                fixed_version=triage.vulnerablility_fixed_version,
            )
            source = resolution.source or "npm_registry"
        else:
            resolution = await version_resolver.resolve(
                parent,
                triage.package,
                triage.vulnerablility_fixed_version,
                current_parent_version=current_parent_version,
            )
            source = "pypi_verified"

        if not resolution.resolved or not resolution.resolved_version:
            return None
        return PackageUpgradeRecommendation(
            package=parent,
            from_version=current_parent_version,
            to_version=resolution.resolved_version,
            minimum_upgradable_version=(
                getattr(resolution, "minimum_upgradable_version", None)
                or ""
            ),
            requires_verification=getattr(resolution, "requires_verification", False),
            source=source,
            candidate_versions=list(getattr(resolution, "candidates_considered", [])),
        )

    @staticmethod
    def _non_breaking_version(current_version: str, candidate_version: str) -> str:
        try:
            current = Version(current_version.lstrip("vV"))
            candidate = Version(candidate_version.lstrip("vV"))
        except InvalidVersion:
            return ""
        return candidate_version if candidate.major == current.major else ""



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
