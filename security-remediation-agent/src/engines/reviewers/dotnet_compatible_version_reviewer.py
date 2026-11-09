"""Review stable same-major NuGet candidates without modifying security fixes."""
import logging

from ...models.remediation_plan import RemediationPlan
from ...tools.ecosystem_manifest_tool import ManifestTool
from .update_triage import add_update_triage
from ..resolvers.recommendation_resolver.dotnet_recommendation_resolver import (
    DotNetRecommendationResolver,
    NuGetResolutionError,
)

logger = logging.getLogger(__name__)
NUGET_ECOSYSTEMS = frozenset({"nuget"})


class DotNetCompatibleVersionReviewer:
    """Enrich NuGet recommendations with stable same-major registry candidates.

    Core idea: review each project once without replacing security-fix evidence;
    optionally add non-vulnerable updates. Restore verification happens later."""
    def __init__(self, manifest_tool: ManifestTool, resolver=None, additional_updates: bool = False) -> None:
        self.resolver = resolver or DotNetRecommendationResolver(manifest_tool=manifest_tool)
        self.additional_updates = additional_updates

    async def review(self, remediation_plan: RemediationPlan, repo: dict[str, str], *,
                     ref: str | None = None) -> RemediationPlan:
        """Find project candidates per manifest and preserve their distinction from restore verification."""
        owner = repo.get("owner")
        repository = repo.get("repo") or repo.get("name")
        nuget_manifest_paths = any(
            package.ecosystem.lower() == "nuget"
            and bool(package.manifest_path)
            for bundle in remediation_plan.remediation_plan_bundles
            for package in bundle.packages
        )
        if nuget_manifest_paths and (not owner or not repository):
            raise ValueError("Repository owner and name are required for NuGet review")
        nuget_project_paths: set[str] = set()
        nuget_resolver = self.resolver
        for bundle in remediation_plan.remediation_plan_bundles:
            for package in bundle.packages:
                if package.ecosystem.lower() != "nuget":
                    continue
                if package.manifest_path:
                    nuget_project_paths.add(package.manifest_path)
        nuget_notes = []
        for manifest_path in sorted(nuget_project_paths):
            try:
                project_path = await nuget_resolver.resolve_project_path(
                    owner, repository, manifest_path, ref=ref,
                )
                package_names = {
                    recommendation.package
                    for bundle in remediation_plan.remediation_plan_bundles
                    for triage in bundle.packages
                    if triage.ecosystem.lower() == "nuget" and triage.manifest_path == manifest_path
                    for recommendation in triage.package_upgrade_recommendations
                }
                recommendations = await nuget_resolver.highest_same_major_versions(
                    owner, repository, project_path, ref=ref,
                    package_names=None if self.additional_updates else package_names,
                )
                self.populate_compatible_versions(
                    remediation_plan, recommendations, manifest_path,
                )
                if self.additional_updates:
                    vulnerable = {name.casefold() for name in package_names}
                    for key, version in sorted(recommendations.items()):
                        name = key.removesuffix(":candidate")
                        if key.endswith(":candidate") and name not in vulnerable:
                            add_update_triage(
                                remediation_plan,
                                lambda t: t.ecosystem.lower() == "nuget" and t.manifest_path == manifest_path,
                                name, recommendations.get(f"{name}:requested", ""), version,
                            )
                nuget_notes.append(
                    f"{manifest_path}: stable same-major candidates retrieved; "
                    "not security-verified or restore-tested"
                )
            except NuGetResolutionError as exc:
                logger.warning("NuGet review failed for %s: %s", manifest_path, exc)
                nuget_notes.append(f"{manifest_path}: FAILED: {exc}")
        for note in nuget_notes:
            logger.info("NuGet reconciliation: %s", note)
        return remediation_plan

    @staticmethod
    def populate_compatible_versions(
        remediation_plan: RemediationPlan,
        recommendations: dict[str, str],
        manifest_path: str,
    ) -> None:
        logger.info(
            "Resolved %d NuGet candidate(s) for %s", len(recommendations), manifest_path
        )
        for bundle in remediation_plan.remediation_plan_bundles:
            for triage in bundle.packages:
                if triage.ecosystem.lower() != "nuget" or triage.manifest_path != manifest_path:
                    continue
                for recommendation in triage.package_upgrade_recommendations:
                    candidate = recommendations.get(f"{recommendation.package.casefold()}:candidate")
                    if candidate:
                        recommendation.compatible_version = candidate
                        recommendation.compatible_review_status = "upgrade_found"
