"""Dependabot collection and normalization through the current public API."""
import httpx
import pytest
from src.models.gh.vulnerability_alert import VulnerabilityAlert, build_alerts_by_package
from src.tools import dependabot_alerts_tool as module


def raw(number=1):
    return {"number": number, "dependency": {"package": {"name": "Requests", "ecosystem": "pip"},
            "manifest_path": "api/requirements.txt", "relationship": "direct"},
            "security_advisory": {"severity": "HIGH", "summary": "Requests vulnerability"},
            "security_vulnerability": {"vulnerable_version_range": "<2.32.0",
                                       "first_patched_version": {"identifier": "2.32.0"}}}


def test_model_preserves_identity_manifest_and_fix():
    alert = VulnerabilityAlert.from_dependabot_alert(raw())
    assert (alert.package, alert.ecosystem, alert.severity) == ("Requests", "pip", "high")
    assert (alert.manifest_path, alert.first_patched) == ("api/requirements.txt", "2.32.0")
    assert VulnerabilityAlert.from_dependabot_alert({}) is None
    assert build_alerts_by_package([raw(), {}]) == {"requests": [alert.model_dump()]}


@pytest.mark.asyncio
async def test_fetch_paginates_and_authenticates(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "token")
    original = httpx.AsyncClient
    requests = []
    def handler(request):
        requests.append(request)
        assert request.headers["Authorization"] == "Bearer token"
        if len(requests) == 1:
            return httpx.Response(200, json=[raw()], headers={"Link":
                '<https://api.github.com/repos/o/r/dependabot/alerts?page=2>; rel="next"'})
        return httpx.Response(200, json=[raw(2)])
    monkeypatch.setattr(module.httpx, "AsyncClient", lambda **kw:
                        original(transport=httpx.MockTransport(handler), **kw))
    alerts = await module.dependabot_alerts_tool.ainvoke({"owner": "o", "repo": "r"})
    assert [a.number for a in alerts] == [1, 2]
    assert requests[0].url.params["state"] == "open"
    assert requests[1].url.params["page"] == "2"
