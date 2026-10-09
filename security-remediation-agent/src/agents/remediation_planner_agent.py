import logging

from ..engines.remediation_grouping_engine import RemediationGroupingEngine
from ..models.remediation_plan import (
    RemediationPlan,
    RemeditionPackage,
    RemeditionPackageBundle,
)
from ..models.security_package_triage import SecurityPackageTriage
from ..models.security_remediation_context import SecurityRemediationContext
from packaging.version import InvalidVersion, Version

logger = logging.getLogger(__name__)


class RemediationPlannerAgent:
    @staticmethod
    def _is_non_breaking(current_version: str, candidate_version: str) -> bool:
        try:
            return (
                Version(current_version.lstrip("vV")).major
                == Version(candidate_version.lstrip("vV")).major
            )
        except InvalidVersion:
            return False

    @staticmethod
    def _highest_version(first: str, second: str) -> str:
        if not first:
            return second
        if not second:
            return first
        try:
            return str(max(Version(first.lstrip("vV")), Version(second.lstrip("vV"))))
        except InvalidVersion:
            return first

    @staticmethod
    def _merge_packages(
        target: RemeditionPackage,
        package: SecurityPackageTriage,
    ) -> None:
        if any(existing.package == package.package for existing in target.packages):
            return
        target.packages.append(package)

    @staticmethod
    def _merge_pull_requests(target: RemeditionPackage, pull_requests) -> None:
        for pull in pull_requests:
            if any(existing.pr_number == pull.pr_number for existing in target.remediation_prs):
                continue
            target.remediation_prs.append(pull)

    @staticmethod
    def _merge_remediation_packages(target: RemeditionPackage, source: RemeditionPackage) -> None:
        """Fold a duplicate RemeditionPackage entry (same remediation_package name)
        into the first one seen for that name, keeping the highest remediation
        version and merging their triage-package/PR lists.
        """
        for package in source.packages:
            if not any(
                existing.package == package.package
                for existing in target.packages
            ):
                target.packages.append(package)
        RemediationPlannerAgent._merge_pull_requests(target, source.remediation_prs)

        if not target.current_version and source.current_version:
            target.current_version = source.current_version
        target.remediation_version = RemediationPlannerAgent._highest_version(
            target.remediation_version,
            source.remediation_version,
        )
        target.minimum_upgradable_version = RemediationPlannerAgent._highest_version(
            target.minimum_upgradable_version,
            source.minimum_upgradable_version,
        )

    @staticmethod
    def _dedupe_bundle_packages(
        packages: list[RemeditionPackage],
    ) -> list[RemeditionPackage]:
        """Collapse duplicate entries in a bundle that share the same
        remediation_package name (e.g. the same package reported once as a
        direct dependency and again as a transitive one, such as showdown or
        axios appearing twice under the same group)."""
        deduped: dict[str, RemeditionPackage] = {}
        for package in packages:
            key = package.remediation_package
            if key not in deduped:
                deduped[key] = package
            else:
                RemediationPlannerAgent._merge_remediation_packages(deduped[key], package)
        return list(deduped.values())

    @staticmethod
    def _build_remediation_package_bundles_by_ecosystem(
        remediation_packages: list[RemeditionPackage],
    ) -> list[RemeditionPackageBundle]:
        """Fallback grouping used when Renovate packageRules aren't available."""
        grouped: dict[str, list[RemeditionPackage]] = {}
        for package in remediation_packages:
            group_name = package.ecosystem or "unknown"
            grouped.setdefault(group_name, []).append(package)

        return [
            RemeditionPackageBundle(
                groupName=group_name,
                ecosystem=group_name,
                severity=None,
                packages=RemediationPlannerAgent._dedupe_bundle_packages(packages),
            )
            for group_name, packages in grouped.items()
        ]

    async def _build_remediation_package_bundles(
        self,
        remediation_packages: list[RemeditionPackage],
        repo: dict | None,
    ) -> list[RemeditionPackageBundle]:
        """Group packages using the repository's Renovate packageRules when possible.

        Falls back to grouping by ecosystem if `repo` isn't provided or the
        renovate.json5 config can't be fetched/parsed.
        """
        owner = (repo or {}).get("owner")
        name = (repo or {}).get("name")
        if not owner or not name:
            logger.warning("Repository not provided; grouping remediation packages by ecosystem")
            return self._build_remediation_package_bundles_by_ecosystem(remediation_packages)

        try:
            bundles = await RemediationGroupingEngine.group_packages_from_github(
                remediation_packages, owner, name
            )
        except Exception as e:
            logger.warning(
                "Falling back to ecosystem-based grouping; failed to group by Renovate packageRules for %s/%s: %s",
                owner,
                name,
                e,
            )
            return self._build_remediation_package_bundles_by_ecosystem(remediation_packages)

        for bundle in bundles:
            bundle.packages = self._dedupe_bundle_packages(bundle.packages)
        return bundles

    async def plan(
        self,
        triage_items: list[SecurityPackageTriage],
        context: SecurityRemediationContext,
        repo: dict | None = None,
    ) -> RemediationPlan:
        logger.info(
            "Planning remediation for %d triage items",
            len(triage_items),
        )

        direct_remediation_packages: list[RemeditionPackage] = []
        transitive_remediation_packages: list[RemeditionPackage] = []
        unique_update_packages: dict[str, RemeditionPackage] = {}
        for package in triage_items:
            if not package.istransitive:
                direct_remediation_packages.append(
                    RemeditionPackage(
                        remediation_package=package.package,
                        ecosystem=package.ecosystem,
                        current_version=package.current_version,
                        remediation_version=package.vulnerablility_fixed_version,
                        minimum_upgradable_version=(
                            package.vulnerablility_fixed_version
                            if self._is_non_breaking(
                                package.current_version,
                                package.vulnerablility_fixed_version,
                            )
                            else ""
                        ),
                        packages=[package],
                        remediation_prs=list(package.pull_request_metadata),
                    )
                )
                continue

            if not package.package_upgrade_recommendations:
                logger.warning(
                    "No upgrade recommendation for transitive package %s; skipping",
                    package.package,
                )

            for recommendation in package.package_upgrade_recommendations:
                key = recommendation.package
                if key not in unique_update_packages:
                    unique_update_packages[key] = RemeditionPackage(
                        remediation_package=key,
                        ecosystem=package.ecosystem,
                        current_version=(
                            recommendation.from_version or package.current_version
                        ),
                        remediation_version=recommendation.to_version,
                        minimum_upgradable_version=(
                            recommendation.minimum_upgradable_version
                        ),
                        packages=[package],
                        remediation_prs=list(package.pull_request_metadata),
                    )
                else:
                    update_package = unique_update_packages[key]
                    self._merge_packages(update_package, package)
                    self._merge_pull_requests(
                        update_package,
                        package.pull_request_metadata,
                    )
                    if not update_package.current_version and recommendation.from_version:
                        update_package.current_version = recommendation.from_version

        transitive_remediation_packages = list(unique_update_packages.values())

        all_remediation_packages = [*direct_remediation_packages, *transitive_remediation_packages]
        remediation_plan_bundles = await self._build_remediation_package_bundles(all_remediation_packages, repo)
        plan_result = RemediationPlan(
            remediation_plan_bundles=remediation_plan_bundles,
            summary= context,
        )
        
        return plan_result
