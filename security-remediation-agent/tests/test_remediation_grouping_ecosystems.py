import pytest

from src.engines.remediation_grouping_engine import RemediationGroupingEngine
from src.models.security_package_triage import SecurityPackageTriage


@pytest.mark.parametrize("explicit_group", [False, True])
def test_shared_group_keeps_ecosystems_separate(explicit_group):
    packages = [SecurityPackageTriage(
        package=name, ecosystem=ecosystem,
        vulnerablility_version_range="<2", vulnerablility_fixed_version="2",
    ) for name, ecosystem in [("npm-a", "npm"), ("pip-a", "pip"), ("npm-b", "NPM")]]
    config = {"packageRules": [{
        "matchPackageNames": [package.package for package in packages],
        "groupName": "shared",
    }]} if explicit_group else {}

    bundles = RemediationGroupingEngine.group_packages_by_package_rules(packages, config)

    assert len(bundles) == 2
    assert {bundle.groupName for bundle in bundles} == {"shared" if explicit_group else "default"}
    assert {bundle.ecosystem: [package.package for package in bundle.packages] for bundle in bundles} == {
        "npm": ["npm-a", "npm-b"], "pip": ["pip-a"],
    }
    assert all(package.ecosystem.lower() == bundle.ecosystem
               for bundle in bundles for package in bundle.packages)


@pytest.mark.parametrize("group_name", [None, ""])
def test_unnamed_renovate_group_uses_default(group_name):
    package = SecurityPackageTriage(
        package="a", ecosystem="npm", vulnerablility_version_range="<2", vulnerablility_fixed_version="2",
    )
    [bundle] = RemediationGroupingEngine.group_packages_by_package_rules([package], {
        "packageRules": [{"matchPackageNames": ["a"], "groupName": group_name}],
    })
    assert bundle.groupName == "default"


def test_planner_fallback_groups_by_ecosystem_and_upgrade_type():
    from src.agents.remediation_planner_agent import RemediationPlannerAgent

    packages = [SecurityPackageTriage(
        package=name, ecosystem=ecosystem, current_version=current,
        vulnerablility_version_range="<2", vulnerablility_fixed_version=fixed, severity="high",
    ) for name, ecosystem, current, fixed in [
        ("major", "npm", "1.0.0", "2.0.0"),
        ("minor", "npm", "1.0.0", "1.1.0"),
        ("patch", "npm", "1.0.0", "1.0.1"),
        ("unknown", "npm", "", ""),
        ("python", "pip", "1.0.0", "1.1.0"),
    ]]
    bundles = RemediationPlannerAgent._build_remediation_package_bundles_by_ecosystem(packages)
    assert [(bundle.ecosystem, bundle.groupName) for bundle in bundles] == [
        ("npm", "npm/major"), ("npm", "npm/minor"), ("npm", "npm/patch"),
        ("npm", "default"), ("pip", "pip/minor"),
    ]
    assert sum(len(bundle.packages) for bundle in bundles) == len(packages)
    assert all(bundle.severity == "high" for bundle in bundles)
