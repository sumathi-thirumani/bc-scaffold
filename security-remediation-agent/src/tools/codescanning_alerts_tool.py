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
    owner: str = Field(description="Repository owner or organization.")
    repo: str = Field(description="Repository name.")


async def get_codescanning_alerts(owner: str, repo: str) -> list[dict[str, Any]]:
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
    return [
        alert
        for alert in alerts
        if alert.get("state") == "open"
        and (alert.get("rule") or {}).get("name")
        == LANGUAGE_SPECIFIC_PACKAGE_VULNERABILITY_RULE
    ]


async def normalize(alerts: Iterable[dict[str, Any]]) -> list[CodescanningAlert]:
    codescanning_findings: list[CodescanningAlert] = []

    for alert in alerts:
        codescanning_alert = CodescanningAlert.from_codescanning_alert(alert)
        if codescanning_alert is not None:
            codescanning_findings.append(codescanning_alert)

    return codescanning_findings


@tool(
    "collect_codescanning_alerts",
    args_schema=CodescanningAlertInput,
)
async def codescanning_alerts_tool(owner: str, repo: str) -> list[CodescanningAlert]:
    """Collect open GitHub code scanning alerts for a repository."""
    alerts = await get_codescanning_alerts(owner=owner, repo=repo)

    return await normalize(alerts)
