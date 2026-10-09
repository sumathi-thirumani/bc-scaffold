import httpx
import pytest

from src.utils.manifest_provider import ManifestProvider


def _provider(status: int, body: str = '{"dependencies": {"axios": "^1.0.0"}}'):
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        return httpx.Response(status, text=body if status == 200 else "", headers={"content-type": "text/plain"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return ManifestProvider(token="t", client=client), calls


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

    assert calls["count"] == 2


@pytest.mark.asyncio
async def test_transient_failure_does_not_record_empty_declarations():
    provider, _ = _provider(500)

    assert await provider.declared_packages("o", "r", "package.json") == {}

    key = provider.cache.manifest_cache.key("o", "r", "package.json", None)
    assert provider.cache.manifest_cache.get_packages(key) is None


@pytest.mark.asyncio
async def test_successful_fetch_is_declared_and_cached():
    provider, calls = _provider(200)

    declared = await provider.declared_packages("o", "r", "package.json")
    await provider.get("o", "r", "package.json")

    assert declared == {"axios": "^1.0.0"}
    assert calls["count"] == 1
