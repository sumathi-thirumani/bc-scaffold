import httpx
import pytest

from src.tools.ecosystem_manifest_tool import ManifestTool


def _provider(status: int, body: str = '{"dependencies": {"axios": "^1.0.0"}}'):
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if "/contents/" not in request.url.path:
            return httpx.Response(200, json={"name": "r"})
        calls["count"] += 1
        return httpx.Response(status, text=body if status == 200 else "", headers={"content-type": "text/plain"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    tool = ManifestTool(token="t", client=client)
    async def no_wait(_): pass
    tool._sleep = no_wait
    return tool, calls


@pytest.mark.asyncio
async def test_not_found_is_cached():
    provider, calls = _provider(404)

    assert await provider.get("o", "r", "package.json") is None
    assert await provider.get("o", "r", "package.json") is None

    assert calls["count"] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [403, 429, 500, 503])
async def test_transient_failures_are_not_cached(status):
    provider, calls = _provider(status)

    assert await provider.get("o", "r", "package.json") is None
    assert await provider.get("o", "r", "package.json") is None

    assert calls["count"] == (2 if status == 403 else 6)


@pytest.mark.asyncio
async def test_successful_raw_manifest_is_cached():
    provider, calls = _provider(200)
    assert await provider.get("o", "r", "package.json") == '{"dependencies": {"axios": "^1.0.0"}}'
    await provider.get("o", "r", "package.json")
    assert calls["count"] == 1
    await provider.aclose()
