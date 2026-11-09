"""CLI output contract consumed by run-orchestrator.sh."""
import asyncio
import json
from types import SimpleNamespace as NS
from unittest.mock import AsyncMock

import pytest
import main as cli
from src.models.remediation_plan import RemediationPlan


@pytest.mark.parametrize("empty", [True, False])
def test_cli_emits_one_json_document_and_closes_manifest_tool(monkeypatch, capsys, empty):
    plan = RemediationPlan()
    if not empty:
        from src.models.remediation_plan import RemeditionPackageBundle
        plan.remediation_plan_bundles.append(RemeditionPackageBundle("npm", "default", "high"))
    tool = NS(aclose=AsyncMock())
    monkeypatch.setattr(cli, "configure_logging", lambda: None)
    monkeypatch.setattr(cli, "ManifestTool", lambda **kw: tool)
    monkeypatch.setattr(cli, "SecurityOrchestrator", lambda *a, **kw: NS(run=AsyncMock(return_value=plan)))
    monkeypatch.setattr(cli, "VulnerabilityTriageAgent", lambda **kw: NS())
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    monkeypatch.setattr(cli.sys, "argv", ["main.py", "--owner", "o", "--repo", "r"])
    asyncio.run(cli.async_main())
    output = json.loads(capsys.readouterr().out)
    assert len(output["remediation_plan_bundles"]) == (0 if empty else 1)
    tool.aclose.assert_awaited_once()



@pytest.mark.asyncio
async def test_collectors_keep_stdout_free_for_json(monkeypatch, capsys):
    from src.agents import vulnerability_collector_agent as collector
    from src.agents.artifact_collector_agent import ArtifactCollectorAgent
    from src.models.gh.vulnerability_alert import VulnerabilityAlert
    from src.models.gh.pull_request_metadata import PullRequestMetadata
    from src.models.security_remediation_context import SecurityRemediationContext
    from src.tools.ecosystem_manifest_tool import ManifestTool
    monkeypatch.setattr(collector, 'dependabot_alerts_tool', NS(ainvoke=AsyncMock(
        return_value=[VulnerabilityAlert(package='a', severity='high')])))
    monkeypatch.setattr(collector, 'codescanning_alerts_tool', NS(ainvoke=AsyncMock(return_value=[])))
    repo = {'owner': 'o', 'name': 'r', 'ref': 'release'}
    context = SecurityRemediationContext()
    findings = await collector.VulnerabilityCollectorAgent().collect(repo, context)
    artifacts = ArtifactCollectorAgent(ManifestTool(token='test'))
    artifacts._fetch_pull_requests = AsyncMock(return_value=[PullRequestMetadata(pr_number=1)])
    artifacts._safe_prefetch_manifests = AsyncMock()
    await artifacts.collect(repo, findings, context)
    assert capsys.readouterr().out == ''
