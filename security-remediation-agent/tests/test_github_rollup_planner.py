import pytest

from src.tools import github_rollup_planner as planner


def test_parse_severities_normalizes_csv():
    assert planner.parse_severities("HIGH, medium") == {"high", "medium"}


def test_parse_severities_rejects_invalid_values():
    with pytest.raises(ValueError, match="Unsupported severity values: urgent"):
        planner.parse_severities("high,urgent")


@pytest.mark.asyncio
async def test_build_rollup_plan_uses_collector_tools(monkeypatch):
    async def stub_get_dependabot_alerts(owner, repo, severities=None):
        return [
            {
                "number": 1,
                "html_url": "https://github.com/octo-org/octo-repo/security/dependabot/1",
                "dependency": {"package": {"name": "requests", "ecosystem": "pip"}},
                "security_advisory": {"severity": "high", "summary": "Requests vulnerability"},
                "security_vulnerability": {
                    "vulnerable_version_range": "< 2.32.0",
                    "first_patched_version": {"identifier": "2.32.0"},
                },
            },
            {
                "number": 2,
                "dependency": {"package": {"name": "django", "ecosystem": "pip"}},
                "security_advisory": {"severity": "critical", "summary": "Django vulnerability"},
                "security_vulnerability": {
                    "vulnerable_version_range": "< 4.2.2",
                    "first_patched_version": {"identifier": "4.2.2"},
                },
            },
        ]

    async def stub_get_codescanning_alerts(owner, repo):
        return [{"number": 99}]

    async def stub_get_open_pull_requests(owner, repo):
        return [
            {
                "number": 7,
                "title": "Bump requests from 2.31.0 to 2.32.0",
                "head": {"ref": "dependabot/pip/requests-2.32.0"},
                "html_url": "https://github.com/octo-org/octo-repo/pull/7",
                "user": {"login": "dependabot[bot]"},
            },
            {"number": 8, "title": "Refactor unrelated code"},
        ]

    monkeypatch.setattr(planner, "get_dependabot_alerts", stub_get_dependabot_alerts)
    monkeypatch.setattr(planner, "get_codescanning_alerts", stub_get_codescanning_alerts)
    monkeypatch.setattr(planner, "get_open_pull_requests", stub_get_open_pull_requests)

    plan = await planner.build_rollup_plan(
        owner="octo-org",
        repo="octo-repo",
        base_branch="main",
        run_id="123",
        severities={"critical", "high"},
    )

    assert plan["base_branch"] == "main"
    assert plan["repo_scope"] == "octo-org/octo-repo"
    django_finding = next(
        finding for finding in plan["findings_without_pr"] if finding["package"] == "django"
    )
    assert django_finding["action_type"] == "placeholder_pr"
    assert django_finding["patched_versions"] == ["4.2.2"]
    assert "## Security remediation — django" in django_finding["placeholder_markdown"]
    assert plan["stats"] == {
        "total_open_alerts": 2,
        "total_open_prs_reviewed": 2,
        "total_prs_matched": 1,
        "total_prs_ignored": 1,
        "total_code_scanning_alerts": 1,
        "total_findings_without_pr": 2,
        "total_auto_created_prs": 0,
    }
