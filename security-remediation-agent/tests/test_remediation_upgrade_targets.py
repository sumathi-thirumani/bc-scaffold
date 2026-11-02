import asyncio

from src.agents.remediation_planner_agent import RemediationPlannerAgent
from src.models.security_package_triage import PackageUpgradeRecommendation, SecurityPackageTriage
from src.models.security_remediation_context import SecurityRemediationContext


def test_planner_consolidates_shared_target_in_bundle():
    packages = [SecurityPackageTriage(
        package=child, ecosystem="npm", istransitive=True,
        vulnerablility_version_range="<2", vulnerablility_fixed_version="2",
        package_upgrade_recommendations=[PackageUpgradeRecommendation(
            package="orval", from_version="7.0.0", qualifying_upgrade_versions=versions,
        )],
    ) for child, versions in [("fast-uri", ["7.1.0", "7.2.0", "8.0.0"]),
                              ("undici", ["7.2.0", "8.0.0", "9.0.0"])]]
    plan = asyncio.run(RemediationPlannerAgent().plan(packages, SecurityRemediationContext()))
    assert plan.remediation_plan_bundles[0].upgrade_targets == [{
        "package": "orval", "current_version": "7.0.0", "minimum_fixed_version": "7.2.0",
        "compatible_version": "7.2.0", "highest_fixed_version": "8.0.0",
        "affected_packages": ["fast-uri", "undici"],
    }]
    packages[1].package_upgrade_recommendations[0].qualifying_upgrade_versions = []
    targets = RemediationPlannerAgent._build_upgrade_targets(packages)
    assert len(targets) == 1
    assert targets[0]["minimum_fixed_version"] == ""


def test_direct_target_keeps_known_fix_without_verification():
    package = SecurityPackageTriage(
        package="minimatch", current_version="10.2.5", vulnerablility_version_range="<11.0.1",
        vulnerablility_fixed_version="11.0.1",
    )
    targets = RemediationPlannerAgent._build_upgrade_targets([package])
    assert targets[0]["minimum_fixed_version"] == "11.0.1"


def test_transitive_child_fix_is_not_used_for_parent():
    from src.models.security_package_triage import TransistiveOccurances, TransistiveSourcePackage

    package = SecurityPackageTriage(
        package="child", vulnerablility_version_range="<2", vulnerablility_fixed_version="2",
        istransitive=True, transitive_dependency_occurrences=[TransistiveOccurances(
            package="child", version="1", introducers=[TransistiveSourcePackage(package="parent", version="5")],
        )],
    )
    targets = RemediationPlannerAgent._build_upgrade_targets([package])
    assert targets[0]["package"] == "parent"
    assert targets[0]["minimum_fixed_version"] == ""