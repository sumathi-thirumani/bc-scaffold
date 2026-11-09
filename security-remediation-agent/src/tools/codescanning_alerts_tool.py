from collections.abc import Iterable
from typing import Any

import httpx
from langchain_core.tools import tool
from pydantic import BaseModel, Field

from ..models.gh.codescanning_alert import CodescanningAlert
from .utils.github_api import (
    GITHUB_API_VERSION as GITHUB_API_VERSION,
    PER_PAGE,
    GitHubApiError,
    fetch_paginated_results,
    get_github_headers,
    get_next_link as get_next_link,
)

LANGUAGE_SPECIFIC_PACKAGE_VULNERABILITY_RULE = "LanguageSpecificPackageVulnerability"


class CodescanningAlertInput(BaseModel):
    """Repository coordinates accepted by the code-scanning collection tool."""

    owner: str = Field(description="Repository owner or organization.")
    repo: str = Field(description="Repository name.")


async def get_codescanning_alerts(owner: str, repo: str) -> list[dict[str, Any]]:
    """Fetch open code-scanning alerts and keep package-vulnerability findings.

    GitHub's shared helper handles pagination. A 404 is surfaced with guidance
    because it commonly means code scanning is disabled or the token lacks access.
    """
    url = f"https://api.github.com/repos/{owner}/{repo}/code-scanning/alerts"
    params = {"state": "open", "per_page": PER_PAGE}
    headers = get_github_headers()

    try:
        alerts = await fetch_paginated_results(
            url,
            params,
            headers=headers,
            owner=owner,
            repo=repo,
            resource="code-scanning alerts",
            client_factory=httpx.AsyncClient,
        )
    except GitHubApiError as exc:
        if exc.status_code == 404:
            raise RuntimeError(
                f"Unable to list code scanning alerts for {owner}/{repo}: GitHub returned "
                "404. Confirm code scanning is enabled and GITHUB_TOKEN can read alerts."
            ) from exc
        raise

    return filter_codescanning_alerts(alerts)


def filter_codescanning_alerts(alerts: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep open alerts for the supported package-vulnerability rule only."""
    return [
        alert
        for alert in alerts
        if alert.get("state") == "open"
        and (alert.get("rule") or {}).get("name")
        == LANGUAGE_SPECIFIC_PACKAGE_VULNERABILITY_RULE
    ]


async def normalize(alerts: Iterable[dict[str, Any]]) -> list[CodescanningAlert]:
    """Convert API alert dictionaries into code-scanning finding models."""
    codescanning_findings: list[CodescanningAlert] = []

    for alert in alerts:
        codescanning_alert = CodescanningAlert.from_codescanning_alert(alert)
        # Ignore payloads that lack enough package identity to become findings.
        if codescanning_alert is not None:
            codescanning_findings.append(codescanning_alert)

    return codescanning_findings


@tool(
    "collect_codescanning_alerts",
    args_schema=CodescanningAlertInput,
)
async def codescanning_alerts_tool(owner: str, repo: str) -> list[CodescanningAlert]:
    """Collect, filter, and normalize supported open alerts for one repository."""
    alerts = await get_codescanning_alerts(owner=owner, repo=repo)

    return await normalize(alerts)
