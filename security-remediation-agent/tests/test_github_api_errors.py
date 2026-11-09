import httpx
import pytest

from src.tools.utils.github_api import GitHubApiError, fetch_paginated_results


async def _fetch(status):
    transport = httpx.MockTransport(lambda request: httpx.Response(status, json=[]))
    return await fetch_paginated_results(
        "https://api.github.com/repos/o/r/dependabot/alerts", None,
        headers={}, owner="o", repo="r", resource="Dependabot alerts",
        client_factory=lambda **kwargs: httpx.AsyncClient(transport=transport, **kwargs),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("status,hint", [(401, "invalid, expired or revoked"), (403, "rate limited")])
async def test_auth_failures_explain_how_to_fix_the_token(status, hint):
    with pytest.raises(GitHubApiError, match=f"HTTP {status}.*{hint}") as error:
        await _fetch(status)
    assert error.value.status_code == status


@pytest.mark.asyncio
async def test_other_failures_keep_plain_message():
    with pytest.raises(GitHubApiError) as error:
        await _fetch(500)
    assert str(error.value) == "GitHub request for Dependabot alerts failed with HTTP 500"
