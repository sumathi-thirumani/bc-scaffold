import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from src.agents.artifact_collector_agent import ArtifactCollectorAgent
from src.agents.remediation_artifact_agent import RemediationArtifactAgent, to_jsonable
from src.models.remediation_plan import RemediationPlan
from src.tools.ecosystem_manifest_tool import ManifestTool


@pytest.mark.asyncio
async def test_report_uses_collected_config_without_fetching(tmp_path):
    tool = ManifestTool(token="token")
    tool.repository_tree = AsyncMock(return_value=[])

    async def fetch(owner, repo, path, ref):
        assert ref == "release/test"
        return ('{"extends": ["config:recommended"]}', True) if path == "renovate.json5" else (None, True)

    tool._fetch = AsyncMock(side_effect=fetch)
    await ArtifactCollectorAgent(tool)._prefetch_manifests(
        "owner", "repo", SimpleNamespace(dependabot_alerts=[]), "release/test",
    )
    tool._fetch = AsyncMock(side_effect=AssertionError("Reporter must not fetch"))
    reporter = RemediationArtifactAgent(
        tool, tmp_path / "renovate.json5", tmp_path / "plan.json",
    )
    output = await reporter.report(
        RemediationPlan(), {"owner": "owner", "name": "repo", "ref": "release/test"},
    )
    assert json.loads(output.read_text()) == {"extends": ["config:recommended"], "packageRules": []}
    tool._fetch.assert_not_awaited()


def test_plan_export_is_compact_and_versioned():
    from src.models.gh.vulnerability_alert import VulnerabilityAlert
    from src.models.plan_export import SCHEMA_VERSION, export_plan
    from src.models.remediation_plan import RemeditionPackageBundle
    from src.models.security_package_triage import (
        CandidatePackage, PackageUpgradeRecommendation, SecurityPackageTriage)
    tried = CandidatePackage("fastapi", "0.133.0", False, "FAILED", "needs pydantic>=2.7.0")
    recommendation = PackageUpgradeRecommendation(
        "fastapi", "0.125.0", qualifying_upgrade_versions=[tried, "0.140.0"])
    triage = SecurityPackageTriage(
        "fastapi", "<0.133.0", "0.133.0", manifest_path="api/requirements.txt",
        vulnerabilities=[VulnerabilityAlert(ghsa_id="GHSA-x", summary="long text", url="https://x")],
        package_upgrade_recommendations=[recommendation])
    plan = RemediationPlan([RemeditionPackageBundle("pip", "g", "high", [triage])])

    exported = to_jsonable(export_plan(plan))
    package = exported["bundles"][0]["packages"][0]
    assert exported["schema_version"] == SCHEMA_VERSION
    assert package["vulnerabilities"][0].keys().isdisjoint({"summary", "url", "package"})
    rec = package["recommendations"][0]
    assert rec["candidates"] == ["0.133.0", "0.140.0"]
    assert rec["verification"] == [
        {"version": "0.133.0", "status": "FAILED", "message": "needs pydantic>=2.7.0"}]


@pytest.mark.asyncio
async def test_uncollected_config_does_not_overwrite_output(tmp_path):
    output = tmp_path / "renovate.json5"
    output.write_text('{"extends": ["existing"]}')
    reporter = RemediationArtifactAgent(ManifestTool(token="token"), output, tmp_path / "plan.json")
    with pytest.raises(ValueError, match="not collected"):
        await reporter.report(RemediationPlan(), {"owner": "owner", "name": "repo"})
    assert json.loads(output.read_text()) == {"extends": ["existing"]}
    assert (tmp_path / "plan.json").exists()
