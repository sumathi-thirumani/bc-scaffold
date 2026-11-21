"""Group triaged findings into remediation bundles without losing their evidence."""
import logging

from ..agents.llm.grouping_recommendation_agent import GroupingRecommendationAgent
from ..engines.grouping import (
    DefaultGroupingEngine, LlmGroupingEngine, RenovateGroupingEngine, UpgradeTargetBuilder,
)
from ..models.remediation_plan import RemediationPlan, RemeditionPackageBundle
from ..models.security_package_triage import SecurityPackageTriage
from ..models.security_remediation_context import SecurityRemediationContext
from ..tools.ecosystem_manifest_tool import ManifestTool

logger = logging.getLogger(__name__)


class RemediationPlannerAgent:
    """Turn reviewed triage findings into remediation bundles and upgrade targets.

    Core idea: apply repository Renovate groups, or ecosystem/upgrade-type defaults,
    then consolidate shared parents within each manifest using common qualifying
    versions and reviewed compatibility limits. Without Renovate groups, LLM grouping is used
    when enabled. Verification runs after planning."""
    def __init__(self, manifest_tool: ManifestTool | None = None,
                 grouping_recommendation_agent: GroupingRecommendationAgent | None = None) -> None:
        self.manifest_tool = manifest_tool
        self.grouping_recommendation_agent = grouping_recommendation_agent

    async def _build_remediation_package_bundles(
        self, triage_items: list[SecurityPackageTriage], repo: dict | None,
        ref: str | None = None,
    ) -> list[RemeditionPackageBundle]:
        owner = (repo or {}).get("owner")
        name = (repo or {}).get("repo") or (repo or {}).get("name")
        if owner and name:
            try:
                bundles = await RenovateGroupingEngine.group_packages_from_github(
                    triage_items, owner, name, ref, manifest_tool=self.manifest_tool)
                if bundles is not None:
                    for bundle in bundles:
                        bundle.severity = DefaultGroupingEngine.bundle_severity(bundle.packages)
                    return bundles
            except Exception as exc:
                logger.warning("Cannot group by Renovate config for %s/%s; using fallback: %s",
                               owner, name, exc)
        if self.grouping_recommendation_agent is not None:
            try:
                return await LlmGroupingEngine.group_packages(triage_items, self.grouping_recommendation_agent)
            except Exception as exc:
                logger.warning("LLM grouping failed; using default grouping: %s", exc)
        return DefaultGroupingEngine.group_packages(triage_items)

    async def plan(
        self, triage_items: list[SecurityPackageTriage], context: SecurityRemediationContext,
        repo: dict | None = None, ref: str | None = None,
    ) -> RemediationPlan:
        """Group reviewed triage items and retain the run summary; targets are built after verification."""
        logger.info("Planning remediation for %d triage items", len(triage_items))
        bundles = await self._build_remediation_package_bundles(triage_items, repo, ref)
        remediation_plan = RemediationPlan(
            remediation_plan_bundles=bundles,
            summary=context,
        )
        return remediation_plan

    @classmethod
    def populate_upgrade_targets(cls, remediation_plan: RemediationPlan) -> None:
        """Rebuild consolidated targets from the current recommendations in each bundle."""
        for bundle in remediation_plan.remediation_plan_bundles:
            bundle.upgrade_targets = UpgradeTargetBuilder.build(bundle.packages)
