"""Add non-vulnerable package updates to the existing bundle of the manifest they belong to."""
from collections.abc import Callable

from ...models.remediation_plan import RemediationPlan
from ...models.security_package_triage import PackageUpgradeRecommendation, SecurityPackageTriage


def add_update_triage(
    plan: RemediationPlan,
    in_manifest: Callable[[SecurityPackageTriage], bool],
    package: str,
    current: str,
    version: str,
) -> None:
    """`in_manifest` selects the triages of the manifest; the update joins the first one's bundle."""
    for bundle in plan.remediation_plan_bundles:
        anchor = next((t for t in bundle.packages if in_manifest(t)), None)
        if anchor is None:
            continue
        if any(t.package == package and t.manifest_path == anchor.manifest_path for t in bundle.packages):
            return
        recommendation = PackageUpgradeRecommendation(
            package=package, from_version=current, qualifying_upgrade_versions=[version],
            compatible_review_status="upgrade_found",
        )
        recommendation.compatible_version = version
        bundle.packages.append(SecurityPackageTriage(
            package=package, vulnerablility_version_range="", vulnerablility_fixed_version="",
            current_version=current, ecosystem=anchor.ecosystem, manifest_path=anchor.manifest_path,
            package_upgrade_recommendations=[recommendation], is_update=True,
        ))
        return
