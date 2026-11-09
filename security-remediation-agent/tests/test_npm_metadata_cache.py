import asyncio

import httpx
import pytest

from src.engines.resolvers.recommendation_resolver.npm_recommendation_resolver import NpmMetadataClient
from src.engines.resolvers.recommendation_resolver_factory import RecommendationResolverFactory


@pytest.mark.asyncio
async def test_requests_are_shared_within_run_but_fresh_in_next_run():
    calls = []

    async def handler(request):
        calls.append(request)
        await asyncio.sleep(0)
        return httpx.Response(200, json={"revision": len(calls)})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        factory = RecommendationResolverFactory()
        factory.npm_metadata = NpmMetadataClient(client)
        first = factory.create("npm")
        second = factory.create("npm")
        assert first.metadata is second.metadata
        assert await asyncio.gather(
            first.metadata.get("Example"), second.metadata.get("example"),
        ) == [{"revision": 1}, {"revision": 1}]
        assert await first.metadata.get("example") == {"revision": 1}
        previous = factory.npm_metadata
        factory.begin_run()
        assert factory.npm_metadata is not previous
        factory.npm_metadata._client = client
        assert await factory.create("npm").metadata.get("example") == {"revision": 2}
        assert len(calls) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [404, "invalid"])
async def test_failed_metadata_is_not_cached(failure):
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(404) if failure == 404 else httpx.Response(200, json=[])
        return httpx.Response(200, json={"versions": {}})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        metadata = NpmMetadataClient(client)
        with pytest.raises((httpx.HTTPStatusError, ValueError)):
            await metadata.get("example")
        assert await metadata.get("example") == {"versions": {}}
        assert calls == 2


@pytest.mark.asyncio
async def test_transient_errors_are_retried_and_persistent_ones_raise():
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        return httpx.Response(429 if calls == 1 else 200, json={"versions": {}})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        assert await NpmMetadataClient(client, retry_delay=0).get("a") == {"versions": {}}
        assert calls == 2

    attempts = 0

    def always_503(request):
        nonlocal attempts
        attempts += 1
        return httpx.Response(503)

    async with httpx.AsyncClient(transport=httpx.MockTransport(always_503)) as client:
        with pytest.raises(httpx.HTTPStatusError):
            await NpmMetadataClient(client, retry_delay=0).get("b")
    assert attempts == 3


@pytest.mark.asyncio
async def test_cancelled_waiter_does_not_drop_shared_request():
    started = asyncio.Event()
    release = asyncio.Event()
    calls = 0

    async def handler(request):
        nonlocal calls
        calls += 1
        started.set()
        await release.wait()
        return httpx.Response(200, json={"versions": {}})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        metadata = NpmMetadataClient(client)
        waiter = asyncio.create_task(metadata.get("example"))
        await started.wait()
        waiter.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiter
        assert "example" in metadata._inflight
        release.set()
        assert await metadata.get("example") == {"versions": {}}
        assert await metadata.get("example") == {"versions": {}}
        assert calls == 1


@pytest.mark.asyncio
async def test_independent_clients_do_not_share_metadata():
    async with httpx.AsyncClient(transport=httpx.MockTransport(
        lambda request: httpx.Response(200, json={"source": "first"}),
    )) as first, httpx.AsyncClient(transport=httpx.MockTransport(
        lambda request: httpx.Response(200, json={"source": "second"}),
    )) as second:
        assert await NpmMetadataClient(first).get("example") == {"source": "first"}
        assert await NpmMetadataClient(second).get("example") == {"source": "second"}
