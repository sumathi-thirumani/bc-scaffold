import asyncio

import httpx
import pytest

from src.tools import repository_context_tool as tool
from src.tools.utils.github_api import GitHubApiError


def _run(monkeypatch, routes):
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    real = httpx.AsyncClient

    def handler(request):
        suffix = request.url.path.split("/repos/sumathi-thirumani/unified-scheduling")[1].lstrip("/")
        status, body = routes[suffix]
        return httpx.Response(status, json=body)

    monkeypatch.setattr(tool.httpx, "AsyncClient",
                        lambda **kw: real(transport=httpx.MockTransport(handler), **kw))
    return asyncio.run(tool.get_repository_context("sumathi-thirumani", "unified-scheduling"))


REPO = {"name": "unified-scheduling", "owner": {"login": "sumathi-thirumani"},
        "private": True, "default_branch": "develop", "description": "d"}


def test_enabled_features_and_metadata(monkeypatch):
    ctx = _run(monkeypatch, {"": (200, REPO), "vulnerability-alerts": (204, None),
                             "code-scanning/alerts": (200, [])})
    assert (ctx.owner, ctx.repo, ctx.ref, ctx.isPrivate) == ("sumathi-thirumani", "unified-scheduling", "develop", True)
    assert ctx.dependabotEnabled is True and ctx.codeScanningEnabled is True


def test_disabled_features_are_false(monkeypatch):
    ctx = _run(monkeypatch, {"": (200, REPO), "vulnerability-alerts": (404, {}),
                             "code-scanning/alerts": (404, {})})
    assert ctx.dependabotEnabled is False and ctx.codeScanningEnabled is False


def test_repository_failure_raises(monkeypatch):
    with pytest.raises(GitHubApiError):
        _run(monkeypatch, {"": (404, {})})
