import logging

import pytest

from src.models.gh.codescanning_alert import CodescanningAlert
from src.tools.utils import version_bump_resolver


def test_codescanning_alert_handles_null_severity_and_rule_id():
    alert = CodescanningAlert.from_codescanning_alert(
        {
            "number": 1,
            "rule": {"name": "some-rule", "id": None},
            "security_severity_level": None,
        }
    )

    assert alert is not None
    assert alert.severity == "unknown"
    assert alert.rule_id == ""


def test_codescanning_alert_normalizes_severity():
    alert = CodescanningAlert.from_codescanning_alert(
        {"rule": {"name": "r", "id": "py/x"}, "security_severity_level": "HIGH"}
    )

    assert alert.severity == "high"
    assert alert.rule_id == "py/x"


def test_version_bump_resolver_uses_module_logger():
    assert version_bump_resolver.logger.name == version_bump_resolver.__name__
    assert version_bump_resolver.logger.name != "asyncio"


def test_title_fallback_is_not_logged_at_info(caplog):
    with caplog.at_level(logging.INFO):
        version_bump_resolver.get_version_bumps(
            "dependabot[bot]", "Bump requests from 2.31.0 to 2.32.0", ""
        )

    assert "falling back to PR title" not in caplog.text


@pytest.mark.asyncio
async def test_pull_requests_tool_skips_prs_with_null_user(monkeypatch):
    from src.tools import pull_requests_tool as module

    async def fake_open_pull_requests(owner, repo):
        return [{"number": 1, "user": None}]

    monkeypatch.setattr(module, "get_open_pull_requests", fake_open_pull_requests)

    result = await module.pull_requests_tool.ainvoke({"owner": "o", "repo": "r"})

    assert result == []


def test_review_output_is_truncated_for_logging():
    from src.agents.vulnerability_reviewer_agent import VulnerabilityReviewerAgent

    truncated = VulnerabilityReviewerAgent._truncate_output("x" * 5000, limit=100)

    assert truncated.startswith("x" * 100)
    assert "4900 more characters" in truncated
    assert VulnerabilityReviewerAgent._truncate_output("short", limit=100) == "short"
