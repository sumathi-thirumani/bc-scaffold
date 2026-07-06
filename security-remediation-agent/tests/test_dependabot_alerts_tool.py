from types import SimpleNamespace

import pytest

from src.agents import vulnerability_collector_agent as agent_module
from src.agents.vulnerability_collector_agent import vulnerabilityCollectorAgent
from src.tools.github_vulnerability_collector import dependabot_alerts_tool as tool_module
from src.tools.github_vulnerability_collector.dependabot_alerts_tool import (
    DependabotAlertInput,
    dependabot_alerts_tool,
    get_dependabot_alerts,
)
from src.tools.github_vulnerability_collector.model.vulnerability_alert import (
    VulnerabilityAlert,
    build_alerts_by_package,
)


class StubResponse:
    def __init__(self, data, headers=None):
        self.data = data
        self.headers = headers or {}

    def raise_for_status(self):
        return None

    def json(self):
        return self.data


class StubAsyncClient:
    requests = []
    pages = []
    links = []
    headers = None
    timeout = None

    def __init__(self, *, headers, timeout):
        type(self).headers = headers
        type(self).timeout = timeout

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        return None

    async def get(self, url, params):
        type(self).requests.append({"url": url, "params": params})
        return StubResponse(type(self).pages.pop(0), {"Link": type(self).links.pop(0)})


def test_dependabot_alert_input_normalizes_severities():
    alert_input = DependabotAlertInput(owner="octo-org", repo="octo-repo", severities=["HIGH"])

    assert alert_input.severities == ["high"]


def test_dependabot_alert_input_rejects_invalid_severities():
    with pytest.raises(ValueError, match="Unsupported Dependabot severity values: urgent"):
        DependabotAlertInput(owner="octo-org", repo="octo-repo", severities=["urgent"])


def test_build_alerts_by_package_normalizes_dependabot_alerts():
    alerts = [
        {
            "number": 1,
            "html_url": "https://github.com/octo-org/octo-repo/security/dependabot/1",
            "dependency": {"package": {"name": "Requests", "ecosystem": "pip"}},
            "security_advisory": {
                "summary": "Requests vulnerability",
                "severity": "HIGH",
                "cvss": {"score": 8.1},
                "cve_id": "CVE-2024-0001",
                "ghsa_id": "GHSA-abcd",
            },
            "security_vulnerability": {
                "vulnerable_version_range": "< 2.32.0",
                "first_patched_version": {"identifier": "2.32.0"},
            },
        },
        {
            "number": 2,
            "dependency": {"package": {"name": "requests", "ecosystem": "pip"}},
            "security_advisory": {},
            "security_vulnerability": {},
        },
        {
            "number": 3,
            "dependency": {"package": {"ecosystem": "pip"}},
        },
    ]

    alerts_by_package = build_alerts_by_package(alerts)

    assert alerts_by_package == {
        "requests": [
            {
                "number": 1,
                "package": "Requests",
                "url": "https://github.com/octo-org/octo-repo/security/dependabot/1",
                "summary": "Requests vulnerability",
                "severity": "high",
                "cvss": 8.1,
                "cve_id": "CVE-2024-0001",
                "ghsa_id": "GHSA-abcd",
                "ecosystem": "pip",
                "vulnerable_range": "< 2.32.0",
                "first_patched": "2.32.0",
                "relationship": "",
            },
            {
                "number": 2,
                "package": "requests",
                "url": "",
                "summary": "",
                "severity": "unknown",
                "cvss": None,
                "cve_id": "",
                "ghsa_id": "",
                "ecosystem": "pip",
                "vulnerable_range": "",
                "first_patched": "",
                "relationship": "",
            },
        ]
    )


def test_vulnerability_alert_model_normalizes_dependabot_alert():
    vulnerability_alert = VulnerabilityAlert.from_dependabot_alert(
        {
            "number": 1,
            "html_url": "https://github.com/octo-org/octo-repo/security/dependabot/1",
            "dependency": {"package": {"name": "Requests", "ecosystem": "pip"}},
            "security_advisory": {
                "summary": "Requests vulnerability",
                "severity": "HIGH",
                "cvss": {"score": 8.1},
                "cve_id": "CVE-2024-0001",
                "ghsa_id": "GHSA-abcd",
            },
            "security_vulnerability": {
                "vulnerable_version_range": "< 2.32.0",
                "first_patched_version": {"identifier": "2.32.0"},
            },
        }
    )

    assert vulnerability_alert is not None
    assert vulnerability_alert.model_dump() == {
        "number": 1,
        "package": "Requests",
        "url": "https://github.com/octo-org/octo-repo/security/dependabot/1",
        "summary": "Requests vulnerability",
        "severity": "high",
        "cvss": 8.1,
        "cve_id": "CVE-2024-0001",
        "ghsa_id": "GHSA-abcd",
        "ecosystem": "pip",
        "vulnerable_range": "< 2.32.0",
        "first_patched": "2.32.0",
        "relationship": "",
    }


@pytest.mark.asyncio
async def test_get_dependabot_alerts_uses_github_filters_and_paginates(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "token")
    monkeypatch.setattr(tool_module.httpx, "AsyncClient", StubAsyncClient)
    StubAsyncClient.requests = []
    StubAsyncClient.pages = [
        [{"number": index} for index in range(tool_module.PER_PAGE)],
        [{"number": tool_module.PER_PAGE}],
    ]
    StubAsyncClient.links = [
        '<https://api.github.com/repositories/1/dependabot/alerts?page=2>; rel="next"',
        "",
    ]

    alerts = await get_dependabot_alerts("octo-org", "octo-repo", severities=["high"])

    assert len(alerts) == tool_module.PER_PAGE + 1
    assert StubAsyncClient.headers["Authorization"] == "Bearer token"
    assert StubAsyncClient.requests == [
        {
            "url": "https://api.github.com/repos/octo-org/octo-repo/dependabot/alerts",
            "params": {
                "state": "open",
                "severity": "high",
                "per_page": tool_module.PER_PAGE,
            },
        },
        {
            "url": "https://api.github.com/repositories/1/dependabot/alerts?page=2",
            "params": None,
        },
    ]


@pytest.mark.asyncio
async def test_dependabot_alerts_tool_invokes_fetcher(monkeypatch):
    async def stub_get_dependabot_alerts(owner, repo, severities=None):
        return [
            {
                "number": 1,
                "html_url": f"https://github.com/{owner}/{repo}/security/dependabot/1",
                "dependency": {"package": {"name": "requests", "ecosystem": "pip"}},
                "security_advisory": {
                    "summary": "Requests vulnerability",
                    "severity": severities[0],
                },
                "security_vulnerability": {},
            }
        ]

    monkeypatch.setattr(tool_module, "get_dependabot_alerts", stub_get_dependabot_alerts)

    alerts = await dependabot_alerts_tool.ainvoke(
        {"owner": "octo-org", "repo": "octo-repo", "severities": ["critical"]}
    )

    assert [alert.model_dump() for alert in alerts] == [
        {
            "number": 1,
            "package": "requests",
            "url": "https://github.com/octo-org/octo-repo/security/dependabot/1",
            "summary": "Requests vulnerability",
            "severity": "critical",
            "cvss": None,
            "cve_id": "",
            "ghsa_id": "",
            "ecosystem": "pip",
            "vulnerable_range": "",
            "first_patched": "",
            "relationship": "",
        }
    ]


@pytest.mark.asyncio
async def test_vulnerability_collector_agent_uses_dependabot_tool(monkeypatch):
    class StubDependabotAlertsTool:
        async def ainvoke(self, tool_input):
            return [{"dependabot_tool_input": tool_input}]

    class StubCodeScanningAlertsTool:
        async def ainvoke(self, tool_input):
            return [{"codescanning_tool_input": tool_input}]

    monkeypatch.setattr(agent_module, "dependabot_alerts_tool", StubDependabotAlertsTool())
    monkeypatch.setattr(agent_module, "codescanning_alerts_tool", StubCodeScanningAlertsTool())

    alerts = await vulnerabilityCollectorAgent().collect(
        SimpleNamespace(owner="octo-org", name="octo-repo")
    )

    assert alerts == agent_module.SecurityFindings(
        dependabot_alerts=[
            {"dependabot_tool_input": {"owner": "octo-org", "repo": "octo-repo"}}
        ],
        codescanning_alerts=[
            {"codescanning_tool_input": {"owner": "octo-org", "repo": "octo-repo"}}
        ],
    }
