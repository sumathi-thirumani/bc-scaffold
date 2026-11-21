import pytest

from src.engines.grouping import DefaultGroupingEngine, RenovateGroupingEngine
from src.models.security_package_triage import SecurityPackageTriage
from src.models.security_package_triage import PackageUpgradeRecommendation


def _transitive(*parents):
    return SecurityPackageTriage(
        package="lodash", ecosystem="npm", istransitive=True,
        vulnerablility_version_range="<4.17.21", vulnerablility_fixed_version="4.17.21",
        package_upgrade_recommendations=[PackageUpgradeRecommendation(
            package=name, from_version="1.0.0", qualifying_upgrade_versions=["1.1.0"],
        ) for name in parents],
    )


def test_parent_group_respects_conditions_and_later_override():
    finding = _transitive("@fluentui/react-components")
    rules = [
        {"matchPackageNames": ["*"], "groupName": "all"},
        {"matchManagers": ["npm"], "matchDatasources": ["npm"],
         "matchUpdateTypes": ["minor", "patch"], "matchPackageNames": ["@fluentui/**"],
         "groupName": "Fluent UI"},
        {"matchManagers": ["nuget"], "matchPackageNames": ["*"], "groupName": "wrong manager"},
        {"matchUpdateTypes": ["major"], "matchPackageNames": ["*"], "groupName": "wrong type"},
    ]
    [bundle] = RenovateGroupingEngine.group_packages_by_package_rules([finding], {"packageRules": rules})
    assert bundle.groupName == "Fluent UI"
    assert bundle.packages == [finding]


def test_conflicting_parent_groups_do_not_duplicate_findings(caplog):
    finding = _transitive("@fluentui/react-components", "react-scripts")
    bundles = RenovateGroupingEngine.group_packages_by_package_rules([finding], {"packageRules": [
        {"matchPackageNames": ["@fluentui/**"], "groupName": "Fluent UI"},
    ]})
    assert len(bundles) == 1
    assert bundles[0].groupName == "default"
    assert "different Renovate groups" in caplog.text


def test_unresolved_parent_can_match_name_rule_but_not_update_type():
    from types import SimpleNamespace
    finding = _transitive()
    finding.transitive_dependency_occurrences = [SimpleNamespace(introducers=[
        SimpleNamespace(package="@fluentui/react-components", version="1.0.0")])]
    [bundle] = RenovateGroupingEngine.group_packages_by_package_rules([finding], {"packageRules": [
        {"matchPackageNames": ["@fluentui/**"], "groupName": "Fluent UI"},
        {"matchUpdateTypes": ["minor"], "groupName": "unknown update must not match"},
    ]})
    assert bundle.groupName == "Fluent UI"


def test_unsupported_conditions_and_presets_are_reported(caplog):
    [bundle] = RenovateGroupingEngine.group_packages_by_package_rules([_transitive("parent")], {
        "extends": ["github>bcgov/renovate-config"],
        "packageRules": [{"matchFileNames": ["webapp/**"], "groupName": "unsafe match"}],
    })
    assert bundle.groupName == "default"
    assert "presets are not resolved" in caplog.text
    assert "unsupported selectors" in caplog.text


def test_name_patterns_allow_regex_and_exclusions():
    assert RenovateGroupingEngine._matches("@fluentui/react-components", ["/^@fluentui/", "!**/react-icons"])
    assert not RenovateGroupingEngine._matches("@fluentui/react-icons", ["@fluentui/**", "!**/react-icons"])


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

    bundles = RenovateGroupingEngine.group_packages_by_package_rules(packages, config)

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
    [bundle] = RenovateGroupingEngine.group_packages_by_package_rules([package], {
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
    bundles = DefaultGroupingEngine.group_packages(packages)
    assert [(bundle.ecosystem, bundle.groupName) for bundle in bundles] == [
        ("npm", "npm/major"), ("npm", "npm/minor"), ("npm", "npm/patch"),
        ("npm", "default"), ("pip", "pip/minor"),
    ]
    assert sum(len(bundle.packages) for bundle in bundles) == len(packages)
    assert all(bundle.severity == "high" for bundle in bundles)


import asyncio
from types import SimpleNamespace

from src.agents.llm.grouping_recommendation_agent import GroupingRecommendationAgent, GroupingRecommendations
from src.agents.remediation_planner_agent import RemediationPlannerAgent
from src.models.security_remediation_context import SecurityRemediationContext


class _Recommender(GroupingRecommendationAgent):
    def __init__(self, groups=None, error=None):
        self.groups, self.error = groups or [], error

    async def recommend(self, packages):
        if self.error:
            raise self.error
        return GroupingRecommendations.model_validate({"groups": self.groups})


def _plan(recommender):
    planner = RemediationPlannerAgent(grouping_recommendation_agent=recommender)
    return asyncio.run(planner.plan(
        [_transitive("react"), _transitive("left-pad")], SecurityRemediationContext()))


def test_llm_grouping_used_without_renovate_config():
    plan = _plan(_Recommender([{"name": "web", "packages": ["react", "left-pad"]}]))
    assert [b.groupName for b in plan.remediation_plan_bundles] == ["web"]


def test_llm_conflicting_targets_and_failure_fall_back():
    split = _plan(_Recommender([{"name": "a", "packages": ["react"]}, {"name": "b", "packages": ["left-pad"]}]))
    assert {b.groupName for b in split.remediation_plan_bundles} == {"a", "b"}
    failed = _plan(_Recommender(error=RuntimeError("ollama down")))
    assert [b.groupName for b in failed.remediation_plan_bundles] == ["npm/minor"]
    assert [b.groupName for b in _plan(None).remediation_plan_bundles] == ["npm/minor"]
