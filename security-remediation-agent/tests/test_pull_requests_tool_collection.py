import httpx
import pytest

from src.models.gh.pull_request_metadata import VersionBump
from src.tools import pull_requests_tool as module


@pytest.fixture(autouse=True)
def _token(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "token")


@pytest.mark.parametrize("user", [
    {"login": "dependabot[bot]"},
    {"login": "renovate[bot]"},
    {"login": "renovate-bot"},
    {"login": "renovate"},
    {"login": "app/renovate"},
])
def test_bot_accounts_are_detected(user):
    assert module._is_bot(user)


@pytest.mark.parametrize("user", [
    {"login": "abbot"}, {"login": "robotics-team"}, {"login": "alice"},
    {"login": "custom", "type": "Bot"}, {"login": "github-actions[bot]"}, None, {},
])
def test_humans_with_bot_in_name_are_not_bots(user):
    assert not module._is_bot(user)


def test_review_needed_only_for_unparsed_conflicting_or_forced():
    bump = VersionBump(package="requests", from_version="1.0", to_version="2.0")
    other = VersionBump(package="Requests", from_version="1.0", to_version="3.0")
    assert module._needs_dependency_review([], False)
    assert module._needs_dependency_review([bump], True)
    assert module._needs_dependency_review([bump, other], False)
    assert not module._needs_dependency_review([bump, bump], False)


def _pr(number, login, title="Bump requests from 1.0 to 2.0"):
    return {
        "number": number,
        "title": title,
        "body": "",
        "user": {"login": login},
        "head": {"ref": "dependabot/pip/requests-2.0"},
    }


@pytest.mark.asyncio
async def test_non_bot_prs_are_skipped(monkeypatch):
    async def fake_open(owner, repo):
        return [_pr(1, "abbot"), _pr(2, "dependabot[bot]")]

    monkeypatch.setattr(module, "get_open_pull_requests", fake_open)
    result = await module.pull_requests_tool.ainvoke({"owner": "o", "repo": "r"})
    assert [item.pr_number for item in result] == [2]


@pytest.mark.asyncio
async def test_review_http_error_keeps_pattern_bumps(monkeypatch):
    async def fake_open(owner, repo):
        return [_pr(1, "dependabot[bot]", title="Bump dependencies")]

    def failing_review(*args, **kwargs):
        raise httpx.ConnectError("boom")

    monkeypatch.setattr(module, "get_open_pull_requests", fake_open)
    monkeypatch.setattr(module, "extract_version_changes", failing_review)
    result = await module.pull_requests_tool.ainvoke(
        {"owner": "o", "repo": "r", "enable_dependency_review": True})
    assert [item.pr_number for item in result] == [1]


@pytest.mark.asyncio
async def test_pull_request_url_quotes_owner_and_repo(monkeypatch):
    seen = {}

    async def fake_paginated(url, *args, **kwargs):
        seen["url"] = url
        return []

    monkeypatch.setattr(module, "fetch_paginated_results", fake_paginated)
    await module.get_open_pull_requests("a/b", "c d")
    assert seen["url"] == "https://api.github.com/repos/a%2Fb/c%20d/pulls"


def test_null_title_body_and_branch_do_not_break_metadata():
    from src.models.gh.pull_request_metadata import build_pull_request_metadata

    metadata = build_pull_request_metadata(
        "o", "r",
        {"number": 7, "title": None, "body": None, "html_url": None, "head": {"ref": None}, "user": {"login": "renovate[bot]"}},
    )
    assert metadata.pr_number == 7
    assert metadata.pr_title == "" and metadata.pr_branch == "" and metadata.version_bumps == []
