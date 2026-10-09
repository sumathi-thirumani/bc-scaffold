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
from src.models.gh.codescanning_alert import CodescanningAlert
from src.models.gh.pull_request_metadata import PullRequestMetadata
from src.tools.utils.version_bump_resolver import VersionBump
from src.models.gh.vulnerability_alert import VulnerabilityAlert


class StubTool:
    def __init__(self, result):
        self.result = result
        self.inputs = []

    async def ainvoke(self, tool_input):
        self.inputs.append(tool_input)
        return self.result


async def run_pipeline(repo: dict[str, str], pull_requests_tool, *, direct: bool = False):
    context = triage_module.SecurityRemediationContext()
    findings = await VulnerabilityCollectorAgent().collect(repo, context)
    agent = VulnerabilityTriageAgent()
    triage_module.pull_requests_tool = pull_requests_tool
    if direct:
        agent.package_relationship_resolver.populate = _populate_as_direct
    triage_result = await agent.triage(repo, findings, context)
    return await RemediationPlannerAgent().plan(triage_result, context, repo)


async def _populate_as_direct(owner, name, triage_items):
    for item in triage_items:
        item.istransitive = False


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
    monkeypatch.setattr(collector_module, "dependabot_alerts_tool", dependabot_tool)
    monkeypatch.setattr(collector_module, "codescanning_alerts_tool", codescanning_tool)

    bundle = await run_pipeline(
        {"owner": "octo-org", "name": "octo-repo"}, pull_requests_tool, direct=True
    )
    group = bundle.remediation_plan_bundles[0]

    assert len(group.packages) == 1
    plan = group.packages[0]
    assert plan.remediation_package == "requests"
    assert plan.remediation_version == "2.32.0"
    assert [pr.pr_number for pr in plan.remediation_prs] == [7]


@pytest.mark.asyncio
async def test_collect_triage_plan_skips_transitive_packages_without_recommendations(
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

    pull_requests_tool = StubTool([])
    monkeypatch.setattr(triage_module, "pull_requests_tool", pull_requests_tool)
    bundle = await run_pipeline(
        {"owner": "octo-org", "name": "octo-repo"}, pull_requests_tool
    )

    assert bundle.remediation_plan_bundles == []


@pytest.mark.asyncio
async def test_triage_tracks_reviewed_pull_requests_without_redundant_logging(
    monkeypatch, caplog
):
    pull_requests = [
        PullRequestMetadata(
            pr_number=8,
            pr_title="Bump requests",
            pr_branch="dependabot/pip/requests",
            pull_url="https://github.com/octo-org/octo-repo/pull/8",
            version_bumps=[],
            author="dependabot[bot]",
        )
    ]
    monkeypatch.setattr(triage_module, "pull_requests_tool", StubTool(pull_requests))
    context = triage_module.SecurityRemediationContext()

    result = await VulnerabilityTriageAgent().triage(
        {"owner": "octo-org", "name": "octo-repo"},
        collector_module.SecurityFindings(dependabot_alerts=[], codescanning_alerts=[]),
        context,
    )

    assert result == []
    assert context.total_reviewed_prs == 1
    assert "Fetching pull requests for repository" not in caplog.text
    assert "Collected--" not in caplog.text
    assert "Grouped into" not in caplog.text


def test_grouping_selects_highest_fixed_version_across_alerts():
    def alert(ghsa, fixed, vulnerable_range, severity="medium"):
        return VulnerabilityAlert(
            package="Lodash",
            ecosystem="npm",
            severity=severity,
            ghsa_id=ghsa,
            first_patched=fixed,
            vulnerable_range=vulnerable_range,
            manifest_path="package.json",
        )

    findings = collector_module.SecurityFindings(
        dependabot_alerts=[
            alert("GHSA-1", "4.17.5", "<4.17.5"),
            alert("GHSA-2", "4.17.21", "<4.17.21", severity="high"),
            alert("GHSA-3", "4.17.9", "<4.17.9"),
            alert("GHSA-4", "", ">=0"),
        ],
        codescanning_alerts=[],
    )

    items = VulnerabilityTriageAgent().group_vulnerabilities_by_package(findings)

    assert len(items) == 1
    assert items[0].vulnerablility_fixed_version == "4.17.21"
    assert items[0].vulnerablility_version_range == "<4.17.21"
    assert len(items[0].vulnerabilities) == 4


def test_grouping_separates_ecosystems_and_compares_versions_numerically():
    def alert(ecosystem, fixed):
        return VulnerabilityAlert(
            package="requests", ecosystem=ecosystem, first_patched=fixed, vulnerable_range="<9"
        )

    findings = collector_module.SecurityFindings(
        dependabot_alerts=[
            alert("pip", "2.9.0"),
            alert("pip", "2.10.0"),
            alert("npm", "1.0.0"),
        ],
        codescanning_alerts=[],
    )

    items = VulnerabilityTriageAgent().group_vulnerabilities_by_package(findings)
    fixed = {item.ecosystem: item.vulnerablility_fixed_version for item in items}

    assert fixed == {"pip": "2.10.0", "npm": "1.0.0"}
