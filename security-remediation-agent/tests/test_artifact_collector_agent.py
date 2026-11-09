from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from src.agents.artifact_collector_agent import ArtifactCollectorAgent
from src.tools.ecosystem_manifest_tool import RENOVATE_CONFIG_PATHS, ManifestTool
from src.models.security_remediation_context import RepositoryContext, SecurityRemediationContext


@pytest.mark.asyncio
async def test_prefetches_repository_manifests_without_dependabot_alerts():
    tool = ManifestTool(token="token")
    tool.repository_tree = AsyncMock(return_value=[
        {"path": "api/Directory.Packages.props"},
        {"path": "api/Unified.Api.csproj"},
        {"path": "web/package.json"},
        {"path": "web/package-lock.json"},
        {"path": "python/pyproject.toml"},
        {"path": "python/requirements-dev.txt"},
        {"path": "python/uv.lock"},
        {"path": "README.md"},
        {"path": "python/main.py"},
    ])
    tool.get = AsyncMock(return_value="file content")
    agent = ArtifactCollectorAgent(manifest_tool=tool)

    await agent._prefetch_manifests(
        "owner", "repo", SimpleNamespace(dependabot_alerts=[]), "commit-sha"
    )

    fetched_paths = {call.args[2] for call in tool.get.await_args_list}
    assert fetched_paths == set(RENOVATE_CONFIG_PATHS) | {
        "api/Directory.Packages.props",
        "api/Unified.Api.csproj",
        "web/package.json",
        "web/package-lock.json",
        "python/pyproject.toml",
        "python/requirements-dev.txt",
        "python/uv.lock",
    }


@pytest.mark.asyncio
async def test_alerts_for_manifests_missing_from_the_repository_are_dropped():
    tool = ManifestTool(token="token")
    tool.repository_tree = AsyncMock(return_value=[{"path": "api/requirements.txt"}])
    tool.get = AsyncMock(return_value="file content")
    alerts = [
        SimpleNamespace(ecosystem="pip", manifest_path="requirements.txt"),
        SimpleNamespace(ecosystem="pip", manifest_path="api/requirements.txt"),
    ]
    findings = SimpleNamespace(dependabot_alerts=alerts)

    await ArtifactCollectorAgent(manifest_tool=tool)._prefetch_manifests("o", "r", findings, "master")

    assert [a.manifest_path for a in findings.dependabot_alerts] == ["api/requirements.txt"]


@pytest.mark.asyncio
@pytest.mark.parametrize("ref", ["main", "release/test"])
async def test_collection_uses_context_ref_and_refreshes_cache_between_runs(ref):
    tool = ManifestTool(token="token")
    tool.repository_tree = AsyncMock(return_value=[{"path": "package.json"}])
    contents = iter(["first", "second"])

    async def fetch(owner, repo, path, ref):
        return (next(contents), True) if path == "package.json" else (None, True)

    tool._fetch = AsyncMock(side_effect=fetch)
    agent = ArtifactCollectorAgent(manifest_tool=tool)
    agent._fetch_pull_requests = AsyncMock(return_value=[])
    repo = RepositoryContext(
        owner="owner", repo="repo", dependabotEnabled=True,
        codeScanningEnabled=True, ref=ref,
    )
    for expected in ["first", "second"]:
        artifacts = await agent.collect(
            repo, SimpleNamespace(dependabot_alerts=[]), SecurityRemediationContext(),
        )
        assert artifacts.ref == ref
        assert await tool.offline().get("owner", "repo", "package.json", ref) == expected
    assert tool._fetch.await_count == 2 * (1 + len(RENOVATE_CONFIG_PATHS))
    tool.repository_tree.assert_awaited_with("owner", "repo", ref)



@pytest.mark.asyncio
async def test_uses_repository_context_default_branch(monkeypatch):
    from src.agents import artifact_collector_agent as module
    tool = ManifestTool(token='token')
    agent = ArtifactCollectorAgent(tool)
    agent._fetch_pull_requests = AsyncMock(return_value=[])
    agent._safe_prefetch_manifests = AsyncMock()
    lookup = AsyncMock(return_value=SimpleNamespace(ref='develop'))
    monkeypatch.setattr(module, 'get_repository_context', lookup)
    artifacts = await agent.collect({'owner': 'o', 'name': 'r'}, SimpleNamespace(dependabot_alerts=[]),
                                    SecurityRemediationContext())
    assert artifacts.ref == 'develop'
    agent._safe_prefetch_manifests.assert_awaited_once_with('o', 'r', SimpleNamespace(dependabot_alerts=[]), 'develop')
