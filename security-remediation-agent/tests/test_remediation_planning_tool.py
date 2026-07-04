import sys
import types

import pytest

from src.models.remediation_plan import ActionType, FixClass, RemediationPlan
from src.models.security_package_triage import SecurityPackageTriage
from src.tools.github_vulnerability_collector.model.vulnerability_alert import VulnerabilityAlert
from src.tools.remediation_planning_assistant.remediation_planning_tool import (
    build_direct_plan,
    build_transitive_plan,
    derive_action_type,
    derive_fix_class,
)

ECOSYSTEM = "npm"
TRANSITIVE_PACKAGE = "form-data"
TRANSITIVE_RANGE = ">= 4.0.0, < 4.0.6"
TRANSITIVE_FIX_VERSION = "4.0.6"
TRANSITIVE_SOURCE = "axios@0.28.1"


@pytest.fixture(autouse=True)
def stub_sbom_analysis_tool() -> None:
    sys.modules.setdefault(
        "src.tools.github_sbom_analyzer.sbom_analysis_tool",
        types.SimpleNamespace(sbom_analysis_tool=types.SimpleNamespace(ainvoke=None)),
    )


def make_alert(
    *,
    package: str,
    ecosystem: str,
    severity: str,
    ghsa_id: str,
    first_patched: str,
    vulnerable_range: str,
    relationship: str = "",
) -> VulnerabilityAlert:
    return VulnerabilityAlert(
        package=package,
        ecosystem=ecosystem,
        severity=severity,
        ghsa_id=ghsa_id,
        first_patched=first_patched,
        vulnerable_range=vulnerable_range,
        relationship=relationship,
    )


def make_direct_pkg() -> SecurityPackageTriage:
    return SecurityPackageTriage(
        package="demo",
        ecosystem="pip",
        current_version_range="<2.0.0",
        remediated_version="2.0.0",
        vulnerabilities=[
            make_alert(
                package="demo",
                ecosystem="pip",
                severity="high",
                ghsa_id="GHSA-demo",
                first_patched="2.0.0",
                vulnerable_range="<2.0.0",
            )
        ],
    )


def make_transitive_pkg(*, remediated_version: str = TRANSITIVE_FIX_VERSION) -> SecurityPackageTriage:
    transitive_source_package = [TRANSITIVE_SOURCE] if remediated_version else []

    return SecurityPackageTriage(
        package=TRANSITIVE_PACKAGE,
        ecosystem=ECOSYSTEM,
        current_version_range=TRANSITIVE_RANGE,
        remediated_version=remediated_version,
        istransitive=True,
        transitive_source_package=transitive_source_package,
        vulnerabilities=[
            make_alert(
                package=TRANSITIVE_PACKAGE,
                ecosystem=ECOSYSTEM,
                severity="critical",
                ghsa_id="GHSA-form-data",
                first_patched=TRANSITIVE_FIX_VERSION,
                vulnerable_range=TRANSITIVE_RANGE,
                relationship="indirect",
            )
        ],
    )


def assert_placeholder_plan(plan: RemediationPlan, expected_target: str) -> None:
    assert plan.action.action_type == ActionType.PLACEHOLDER_PR
    assert plan.action.target_package == expected_target


def test_fix_direction_without_existing_pr_creates_placeholder_plan() -> None:
    pkg = make_direct_pkg()

    fix_class = derive_fix_class(pkg)

    assert fix_class == FixClass.NON_BREAKING_BUMP
    assert derive_action_type(pkg, fix_class) == ActionType.PLACEHOLDER_PR

    plan = build_direct_plan(pkg)
    assert_placeholder_plan(plan, "demo")
    assert "**Target version:** 2.0.0" in plan.action.placeholder_markdown


def test_critical_transitive_fix_direction_without_pr_creates_placeholder_plan() -> None:
    plan = build_transitive_plan(make_transitive_pkg())

    assert plan.package.effective_severity == "critical"
    assert_placeholder_plan(plan, "axios")
    assert f"`axios >= {TRANSITIVE_FIX_VERSION}`" in plan.action.placeholder_markdown
    assert "### Issue details" in plan.action.placeholder_markdown
    assert f"| Patched vulnerable package version | `{TRANSITIVE_FIX_VERSION}` |" in plan.action.placeholder_markdown
    assert "### Source details" in plan.action.placeholder_markdown
    assert "| Source package to update | `axios` |" in plan.action.placeholder_markdown
    assert f"| Source candidates from dependency graph | {TRANSITIVE_SOURCE} |" in plan.action.placeholder_markdown


def test_transitive_triage_does_not_override_alert_remediated_version() -> None:
    from src.agents.vulnerability_triage_agent import VulnerabilityTriageAgent

    pkg = make_transitive_pkg(remediated_version="")

    VulnerabilityTriageAgent().apply_triage_recommendation(pkg)

    assert pkg.remediated_version == ""
    assert pkg.upgrade_version == ""
