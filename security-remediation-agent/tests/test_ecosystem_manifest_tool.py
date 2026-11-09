import asyncio
import logging

import httpx
import pytest

from src.tools.ecosystem_manifest_tool import ManifestTool


@pytest.mark.parametrize("path", [
    "web/npm-shrinkwrap.json", "build/Dependencies.props", "build/Dependencies.targets",
])
def test_supported_dependency_files_are_discovered(path):
    assert ManifestTool.is_dependency_manifest(path)


def test_shrinkwrap_keeps_its_lockfile_path():
    assert ManifestTool.is_lockfile("web/npm-shrinkwrap.json")
    assert ManifestTool.lockfile_path("npm", "web/npm-shrinkwrap.json") == "web/npm-shrinkwrap.json"


@pytest.mark.asyncio
async def test_cached_repository_file_key_is_logged(caplog):
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, text="{}", headers={"content-type": "text/plain"})
        )
    )
    tool = ManifestTool(token="token", client=client)

    with caplog.at_level(logging.INFO, logger="src.tools.ecosystem_manifest_tool"):
        await tool.get("Owner", "Repo", "package.json", "snapshot")

    expected_key = "Cached repository file with key ('owner', 'repo', 'snapshot', 'package.json')"
    assert expected_key in caplog.text
    await client.aclose()


@pytest.mark.asyncio
async def test_default_branch_tree_and_content_are_cached_without_ref_assumption():
    calls = []

    def handler(request):
        calls.append(request)
        if request.url.path == "/repos/Owner/Repo/git/trees/HEAD":
            assert request.url.params["recursive"] == "1"
            return httpx.Response(200, json={
                "truncated": False,
                "tree": [{"type": "blob", "path": "web/package.json"}],
            })
        assert request.url.path == "/repos/Owner/Repo/contents/web/package.json"
        assert "ref" not in request.url.params
        return httpx.Response(200, text='{"dependencies": {}}')

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        tool = ManifestTool(token="token", client=client)
        for _ in range(2):
            assert await tool.repository_tree("Owner", "Repo") == [{"path": "web/package.json"}]
            assert await tool.get("Owner", "Repo", "web/package.json") == '{"dependencies": {}}'
        assert await tool.offline().get("Owner", "Repo", "web/package.json") == '{"dependencies": {}}'
        assert len(calls) == 2

        tool.clear_cache()
        await tool.repository_tree("Owner", "Repo")
        await tool.get("Owner", "Repo", "web/package.json")
        assert len(calls) == 4


@pytest.mark.asyncio
async def test_explicit_ref_is_sent_to_tree_and_contents():
    seen = []

    def handler(request):
        seen.append((request.url.path, request.url.params.get("ref")))
        if "/git/trees/" in request.url.path:
            return httpx.Response(200, json={"truncated": False, "tree": []})
        return httpx.Response(200, text="x")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        tool = ManifestTool(token="token", client=client)
        await tool.repository_tree("Owner", "Repo", "release")
        await tool.get("Owner", "Repo", "package.json", "release")
    assert seen == [
        ("/repos/Owner/Repo/git/trees/release", None),
        ("/repos/Owner/Repo/contents/package.json", "release"),
    ]


@pytest.mark.asyncio
async def test_concurrent_tree_requests_share_one_fetch_and_return_copies():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json={"truncated": False, "tree": [{"type": "blob", "path": "package.json"}]})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        tool = ManifestTool(token="token", client=client)
        results = await asyncio.gather(*(tool.repository_tree("Owner", "Repo") for _ in range(5)))
        results[0].append({"path": "mutated"})
        assert await tool.repository_tree("Owner", "Repo") == [{"path": "package.json"}]
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_offline_view_reads_cache_without_token_and_never_fetches():
    tool = ManifestTool(token="token")
    cache = tool.cache.manifest_cache
    cache.set(cache.key("Owner", "Repo", "package.json", "HEAD"), "{}")
    view = tool.offline()
    view._token = None
    assert await view.get("Owner", "Repo", "package.json") == "{}"
    with pytest.raises(ValueError):
        await view.repository_tree("Owner", "Repo")


@pytest.mark.asyncio
async def test_rate_limit_backoff_does_not_hold_the_request_semaphore():
    responses = iter([httpx.Response(429), httpx.Response(200, text="ok")])
    tool = ManifestTool(token="token", client=httpx.AsyncClient(
        transport=httpx.MockTransport(lambda request: next(responses))))
    held = []

    async def sleep(_):
        held.append(tool._semaphore.locked() or tool._semaphore._value != 8)

    tool._sleep = sleep
    assert (await tool._send("https://api.github.com/x", "a")).text == "ok"
    assert held == [False]


def test_uv_lock_has_no_relationship_resolver():
    assert ManifestTool.relationship_resolver_kind("pip", "uv.lock") is None
