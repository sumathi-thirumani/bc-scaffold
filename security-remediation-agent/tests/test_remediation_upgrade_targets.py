import asyncio
import pytest

from src.agents.remediation_planner_agent import RemediationPlannerAgent
from src.models.remediation_plan import RemediationPlan, RemeditionPackageBundle
from src.models.security_package_triage import CandidatePackage, PackageUpgradeRecommendation, SecurityPackageTriage
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
        "manifest_path": None, "is_update": False, "verification_status": None, "verification_notes": "",
        "verified_version": "",    }]
    packages[1].package_upgrade_recommendations[0].qualifying_upgrade_versions = []
    targets = RemediationPlannerAgent._build_upgrade_targets(packages)
    assert len(targets) == 1
    assert targets[0]["minimum_fixed_version"] == "7.2.0"


def test_shared_target_uses_maximum_minimum_without_common_candidates():
    packages = [SecurityPackageTriage(
        package=child, istransitive=True,
        vulnerablility_version_range="<2", vulnerablility_fixed_version="2",
        package_upgrade_recommendations=[PackageUpgradeRecommendation(
            package="eslint", from_version="7.0.0", qualifying_upgrade_versions=versions,
        )],
    ) for child, versions in [("brace-expansion", ["7.9.0", "8.0.0"]),
                              ("minimatch", ["7.10.0", "9.0.0"])]]
    targets = RemediationPlannerAgent._build_upgrade_targets(packages)
    assert len(targets) == 1
    assert targets[0]["minimum_fixed_version"] == "7.10.0"
    assert targets[0]["affected_packages"] == ["brace-expansion", "minimatch"]
    packages.reverse()
    assert RemediationPlannerAgent._build_upgrade_targets(packages)[0]["minimum_fixed_version"] == "7.10.0"


def test_direct_target_keeps_known_fix_without_verification():
    package = SecurityPackageTriage(
        package="minimatch", current_version="10.2.5", vulnerablility_version_range="<11.0.1",
        vulnerablility_fixed_version="11.0.1",
    )
    targets = RemediationPlannerAgent._build_upgrade_targets([package])
    assert targets[0]["minimum_fixed_version"] == "11.0.1"


def test_missing_parent_recommendation_has_separate_target_from_known_upgrade():
    from src.models.security_package_triage import TransistiveOccurances, TransistiveSourcePackage

    known = SecurityPackageTriage(
        package="brace-expansion", istransitive=True,
        vulnerablility_version_range="<6", vulnerablility_fixed_version="6",
        package_upgrade_recommendations=[PackageUpgradeRecommendation(
            package="eslint", from_version="10.11.0",
            qualifying_upgrade_versions=["10.12.0", "10.13.0", "10.14.0"],
        )],
    )
    unresolved = SecurityPackageTriage(
        package="minimatch", istransitive=True,
        vulnerablility_version_range="<11.0.1", vulnerablility_fixed_version="11.0.1",
        transitive_dependency_occurrences=[TransistiveOccurances(
            package="minimatch", version="10.2.5",
            introducers=[TransistiveSourcePackage(package="eslint", version="10.11.0")],
        )],
    )
    for packages in ([known, unresolved], [unresolved, known]):
        targets = RemediationPlannerAgent._build_upgrade_targets(packages)
        assert len(targets) == 2
        upgrade = next(target for target in targets if target["minimum_fixed_version"])
        assert upgrade == {
            "package": "eslint", "current_version": "10.11.0", "minimum_fixed_version": "10.12.0",
            "compatible_version": "10.12.0", "highest_fixed_version": "10.14.0",
            "affected_packages": ["brace-expansion"],
            "manifest_path": None, "is_update": False, "verification_status": None, "verification_notes": "", "verified_version": "",
        }
        review = next(target for target in targets if not target["minimum_fixed_version"])
        assert review["affected_packages"] == ["minimatch"]
        assert review["package"] == "eslint"
    unresolved.package_upgrade_recommendations = [PackageUpgradeRecommendation(
        package="eslint", from_version="10.11.0",
    )]
    assert len(RemediationPlannerAgent._build_upgrade_targets([known, unresolved])) == 2


def test_planner_refreshes_targets_after_compatible_version_review():
    recommendation = PackageUpgradeRecommendation(
        package="parent", from_version="1.0.0", qualifying_upgrade_versions=["1.1.0", "1.2.0"],
    )
    package = SecurityPackageTriage(
        package="child", vulnerablility_version_range="<2", vulnerablility_fixed_version="2",
        istransitive=True, package_upgrade_recommendations=[recommendation],
    )
    bundle = RemeditionPackageBundle(ecosystem="npm", groupName="default", severity="high", packages=[package])
    plan = RemediationPlan(remediation_plan_bundles=[bundle])
    RemediationPlannerAgent.populate_upgrade_targets(plan)
    assert bundle.upgrade_targets[0]["compatible_version"] == "1.1.0"
    package.compatible_versions["parent"] = "1.2.0"
    RemediationPlannerAgent.populate_upgrade_targets(plan)
    assert bundle.upgrade_targets[0]["compatible_version"] == "1.2.0"


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


def test_independent_manifests_keep_separate_parent_targets():
    packages = [SecurityPackageTriage(
        package=child, ecosystem="npm", manifest_path=manifest, istransitive=True,
        vulnerablility_version_range="<2", vulnerablility_fixed_version="2",
        package_upgrade_recommendations=[PackageUpgradeRecommendation(
            package="parent", from_version="1.0.0", qualifying_upgrade_versions=[version],
        )],
    ) for child, manifest, version in [
        ("child-a", "web/package.json", "1.1.0"),
        ("child-b", "admin/package.json", "1.2.0"),
    ]]
    targets = RemediationPlannerAgent._build_upgrade_targets(packages)
    assert len(targets) == 2
    assert {target["manifest_path"]: (target["compatible_version"], target["affected_packages"])
            for target in targets} == {
        "web/package.json": ("1.1.0", ["child-a"]),
        "admin/package.json": ("1.2.0", ["child-b"]),
    }

    packages[1].manifest_path = "web\\package.json"
    packages[1].package_upgrade_recommendations[0].qualifying_upgrade_versions = [
        CandidatePackage("parent", "1.1.0"), CandidatePackage("parent", "1.2.0")]
    [merged] = RemediationPlannerAgent._build_upgrade_targets(packages)
    assert merged["manifest_path"] == "web/package.json"
    assert merged["affected_packages"] == ["child-a", "child-b"]


@pytest.mark.parametrize("limits,expected", [
    (("1.1.0", "1.2.0"), ""),
    (("1.3.0", "1.3.0"), "1.3.0"),
    (("1.4.0", "1.3.0"), "1.3.0"),
    (("", "1.3.0"), ""),
    (("invalid", "1.3.0"), ""),
])
def test_shared_target_respects_every_compatibility_limit(limits, expected):
    packages = []
    for child, versions, limit in zip(
        ("a", "b"), (("1.1.0", "1.3.0"), ("1.2.0", "1.3.0")), limits,
    ):
        recommendation = PackageUpgradeRecommendation(
            package="parent", from_version="1.0.0", qualifying_upgrade_versions=list(versions),
        )
        recommendation.compatible_review_status = "upgrade_found"
        packages.append(SecurityPackageTriage(
            package=child, ecosystem="npm", manifest_path="web/package.json", istransitive=True,
            vulnerablility_version_range="<2", vulnerablility_fixed_version="2",
            package_upgrade_recommendations=[recommendation], compatible_versions={"parent": limit},
        ))
    for ordered_packages in (packages, list(reversed(packages))):
        [target] = RemediationPlannerAgent._build_upgrade_targets(ordered_packages)
        assert target["compatible_version"] == expected
        assert target["minimum_fixed_version"] == "1.2.0"
        assert target["highest_fixed_version"] == "1.3.0"
        assert target["affected_packages"] == ["a", "b"]


@pytest.mark.parametrize("count", [1, 2])
@pytest.mark.parametrize("reviewed,preferred,expected", [
    (True, "2.0.0", "1.1.0"),
    (True, "invalid", ""),
    (True, "1.0.0", ""),
    (False, "1.1.0", "1.1.0"),
])
def test_identical_entries_always_validate_compatibility(count, reviewed, preferred, expected):
    packages = []
    for index in range(count):
        recommendation = PackageUpgradeRecommendation(
            package="parent", from_version="1.0.0", qualifying_upgrade_versions=["1.1.0"],
        )
        recommendation.compatible_review_status = "upgrade_found" if reviewed else None
        packages.append(SecurityPackageTriage(
            package=f"child-{index}", ecosystem="npm", manifest_path="package.json", istransitive=True,
            vulnerablility_version_range="<2", vulnerablility_fixed_version="2",
            package_upgrade_recommendations=[recommendation], compatible_versions={"parent": preferred},
        ))
    [target] = RemediationPlannerAgent._build_upgrade_targets(packages)
    assert target["compatible_version"] == expected
    assert target["affected_packages"] == [f"child-{index}" for index in range(count)]
    assert "review_status" not in target


def test_unreviewed_defaults_do_not_cap_shared_candidates():
    packages = []
    for index, versions in enumerate((["1.1.0", "1.2.0"], ["1.2.0"])):
        packages.append(SecurityPackageTriage(
            package=f"child-{index}", ecosystem="npm", manifest_path="package.json", istransitive=True,
            vulnerablility_version_range="<2", vulnerablility_fixed_version="2",
            package_upgrade_recommendations=[PackageUpgradeRecommendation(
                package="parent", from_version="1.0.0", qualifying_upgrade_versions=versions,
            )],
        ))
    [target] = RemediationPlannerAgent._build_upgrade_targets(packages)
    assert target["compatible_version"] == "1.2.0"
