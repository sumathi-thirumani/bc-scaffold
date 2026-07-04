import sys
import types

import pytest

sys.modules.setdefault(
    "src.tools.github_sbom_analyzer.sbom_analysis_tool",
    types.SimpleNamespace(sbom_analysis_tool=types.SimpleNamespace(ainvoke=None)),
)

from src.agents import vulnerability_collector_agent as collector_module
from src.agents import vulnerability_triage_agent as triage_module
from src.agents.remediation_planner_agent import RemediationPlannerAgent
from src.agents.vulnerability_collector_agent import VulnerabilityCollectorAgent
from src.agents.vulnerability_triage_agent import VulnerabilityTriageAgent
from src.engines.policy_engine import package_relationship_lookup as relationship_module
from src.models.remediation_plan import ActionType
from src.tools.github_codescanning_collector.model.codescanning_alert import CodescanningAlert
from src.tools.github_pr_collector.model.pull_request_metadata import PullRequestMetadata
from src.tools.github_pr_collector.utils.version_bump_resolver import VersionBump
from src.tools.github_vulnerability_collector.model.vulnerability_alert import VulnerabilityAlert


class StubTool:
    def __init__(self, result):
        self.result = result
        self.inputs = []

    async def ainvoke(self, tool_input):
        self.inputs.append(tool_input)
        return self.result


async def run_pipeline(repo: dict[str, str]):
    findings = await VulnerabilityCollectorAgent().collect(repo)
    triage_result = await VulnerabilityTriageAgent().triage(repo, findings)
    return await RemediationPlannerAgent().plan(triage_result)


@pytest.mark.asyncio
async def test_collect_triage_plan_matches_existing_direct_remediation_pr(monkeypatch):
    dependabot_alerts = [
        VulnerabilityAlert(
            package="requests",
            ecosystem="pip",
            severity="high",
            ghsa_id="GHSA-requests",
            first_patched="2.32.0",
            vulnerable_range="<2.32.0",
            relationship="direct",
        )
    ]
    codescanning_alerts = [
        CodescanningAlert(
            number=10,
            severity="medium",
            rule_id="py/import-security",
            summary="Import uses a vulnerable dependency",
        )
    ]
    pull_requests = [
        PullRequestMetadata(
            pr_number=7,
            pr_title="Bump requests from 2.31.0 to 2.32.0",
            pr_branch="dependabot/pip/requests-2.32.0",
            pull_url="https://github.com/octo-org/octo-repo/pull/7",
            version_bumps=[
                VersionBump(
                    package="requests",
                    from_version="2.31.0",
                    to_version="2.32.0",
                )
            ],
            author="dependabot[bot]",
        )
    ]

    dependabot_tool = StubTool(dependabot_alerts)
    codescanning_tool = StubTool(codescanning_alerts)
    pull_requests_tool = StubTool(pull_requests)
    sbom_tool = StubTool(
        {
            "mode": "packages",
            "data": {
                "packages": [
                    {
                        "name": "requests",
                        "ecosystem": "pip",
                        "dependency_type": "direct",
                        "source_packages": [],
                    }
                ]
            },
        }
    )

    monkeypatch.setattr(collector_module, "dependabot_alerts_tool", dependabot_tool)
    monkeypatch.setattr(collector_module, "codescanning_alerts_tool", codescanning_tool)
    monkeypatch.setattr(triage_module, "pull_requests_tool", pull_requests_tool)
    monkeypatch.setattr(relationship_module, "sbom_analysis_tool", sbom_tool)

    bundle = await run_pipeline({"owner": "octo-org", "name": "octo-repo"})
    group = bundle.by_severity("high")

    assert group is not None
    assert len(group.plans) == 1
    plan = group.plans[0]
    assert plan.package.name == "requests"
    assert plan.package.relationship == "direct"
    assert plan.package.remediated_version == "2.32.0"
    assert plan.fix.upgrade_version == "2.32.0"
    assert plan.action.action_type == ActionType.ROLLUP_PR
    assert plan.action.pr_number == 7
    assert plan.action.pull_url == "https://github.com/octo-org/octo-repo/pull/7"
    assert dependabot_tool.inputs == [{"owner": "octo-org", "repo": "octo-repo"}]
    assert codescanning_tool.inputs == [{"owner": "octo-org", "repo": "octo-repo"}]


@pytest.mark.asyncio
async def test_collect_triage_plan_uses_nested_sbom_packages_for_transitive_source(
    monkeypatch,
):
    dependabot_alerts = [
        VulnerabilityAlert(
            package="form-data",
            ecosystem="npm",
            severity="critical",
            ghsa_id="GHSA-form-data",
            first_patched="4.0.6",
            vulnerable_range=">=4.0.0,<4.0.6",
            relationship="",
        )
    ]

    monkeypatch.setattr(collector_module, "dependabot_alerts_tool", StubTool(dependabot_alerts))
    monkeypatch.setattr(collector_module, "codescanning_alerts_tool", StubTool([]))
    monkeypatch.setattr(triage_module, "pull_requests_tool", StubTool([]))
    monkeypatch.setattr(
        relationship_module,
        "sbom_analysis_tool",
        StubTool(
            {
                "mode": "packages",
                "data": {
                    "total": 2,
                    "direct": 1,
                    "transitive": 1,
                    "unknown": 0,
                    "packages": [
                        {
                            "name": "axios",
                            "version": "0.28.1",
                            "ecosystem": "npm",
                            "dependency_type": "direct",
                            "source_packages": [],
                        },
                        {
                            "name": "form-data",
                            "version": "4.0.4",
                            "ecosystem": "npm",
                            "dependency_type": "transitive",
                            "source_packages": ["axios@0.28.1"],
                        },
                    ],
                },
            }
        ),
    )

    bundle = await run_pipeline({"owner": "octo-org", "name": "octo-repo"})
    group = bundle.by_severity("critical")

    assert group is not None
    assert len(group.plans) == 1
    plan = group.plans[0]
    assert plan.package.name == "form-data"
    assert plan.package.relationship == "transitive"
    assert plan.package.remediated_version == "4.0.6"
    assert plan.package.transitive_source_package == ["axios@0.28.1"]
    assert plan.action.action_type == ActionType.PLACEHOLDER_PR
    assert plan.action.target_package == "axios"


@pytest.mark.asyncio
async def test_indirect_alert_marks_package_transitive_and_uses_sbom_sources(
    monkeypatch,
) -> None:
    dependabot_alerts = [
        VulnerabilityAlert(
            package="http-proxy-middleware",
            ecosystem="npm",
            severity="high",
            ghsa_id="GHSA-64mm-vxmg-q3vj",
            first_patched="2.0.10",
            vulnerable_range=">= 0.16.0, < 2.0.10",
            relationship="indirect",
        )
    ]

    monkeypatch.setattr(collector_module, "dependabot_alerts_tool", StubTool(dependabot_alerts))
    monkeypatch.setattr(collector_module, "codescanning_alerts_tool", StubTool([]))
    monkeypatch.setattr(triage_module, "pull_requests_tool", StubTool([]))
    monkeypatch.setattr(
        relationship_module,
        "sbom_analysis_tool",
        StubTool(
            {
                "mode": "packages",
                "data": {
                    "packages": [
                        {
                            "name": "http-proxy-middleware",
                            "version": "2.0.9",
                            "ecosystem": "npm",
                            "dependency_type": "direct",
                            "source_packages": ["webpack-dev-server@4.15.2"],
                        },
                    ],
                },
            }
        ),
    )

    bundle = await run_pipeline({"owner": "octo-org", "name": "octo-repo"})
    group = bundle.by_severity("high")

    assert group is not None
    assert len(group.plans) == 1
    plan = group.plans[0]
    assert plan.package.relationship == "transitive"
    assert plan.package.transitive_source_package == ["webpack-dev-server@4.15.2"]
    assert "Type: transitive" in plan.action.placeholder_markdown
    assert "Dependency paths:\n- webpack-dev-server@4.15.2 → http-proxy-middleware" in plan.action.placeholder_markdown
