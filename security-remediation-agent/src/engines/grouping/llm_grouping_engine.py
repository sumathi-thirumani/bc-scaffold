"""LLM-assisted grouping used when a repository has no Renovate configuration."""
import logging

from ...agents.llm.grouping_recommendation_agent import GroupingRecommendationAgent
from ...models.remediation_plan import RemeditionPackageBundle
from ...models.security_package_triage import SecurityPackageTriage
from .default_grouping_engine import DefaultGroupingEngine

logger = logging.getLogger(__name__)
DEFAULT_GROUP = "default"


class LlmGroupingEngine:
    """Group findings by the LLM-recommended groups of their upgrade targets."""

    @staticmethod
    def _targets(package: SecurityPackageTriage) -> list[str]:
        """Upgrade targets as the recommender sees them: direct package plus parent upgrades."""
        names = [] if package.istransitive else [package.package]
        names.extend(rec.package for rec in package.package_upgrade_recommendations)
        return [name for name in names if name]

    @classmethod
    async def group_packages(
        cls, triage_items: list[SecurityPackageTriage], recommender: GroupingRecommendationAgent,
    ) -> list[RemeditionPackageBundle]:
        recommendations = await recommender.recommend(triage_items)
        group_of: dict[str, str] = {}
        for group in recommendations.groups:
            for name in group.packages:
                group_of.setdefault(name, group.name)

        grouped: dict[tuple[str, str], list[SecurityPackageTriage]] = {}
        for package in triage_items:
            ecosystem = package.ecosystem.lower() or "unknown"
            names = {recommender.normalize_package_name(ecosystem, name): name for name in cls._targets(package)}
            lookup = {recommender.normalize_package_name(ecosystem, name): group
                      for name, group in group_of.items()}
            groups = {lookup[key] for key in names if key in lookup}
            if len(groups) > 1:
                logger.warning("Finding %s has upgrade targets in different LLM groups %s; retaining default group",
                               package.package, sorted(groups))
            name = next(iter(groups)) if len(groups) == 1 else DEFAULT_GROUP
            grouped.setdefault((ecosystem, name), []).append(package)

        return [RemeditionPackageBundle(
            ecosystem=ecosystem, groupName=name,
            severity=DefaultGroupingEngine.bundle_severity(members),
            packages=sorted(members, key=lambda item: (item.package.casefold(), item.manifest_path or "")),
        ) for (ecosystem, name), members in sorted(grouped.items())]
