import os
from collections.abc import Iterable
from typing import Any

import httpx
from langchain_core.tools import tool
from pydantic import BaseModel, Field

from .model.codescanning_alert import CodescanningAlert

from ..github_vulnerability_collector.dependabot_alerts_tool import (
    GITHUB_API_VERSION,
    PER_PAGE,
    get_next_link,
)

LANGUAGE_SPECIFIC_PACKAGE_VULNERABILITY_RULE = "LanguageSpecificPackageVulnerability"


class CodeScanningAlertInput(BaseModel):
    owner: str = Field(description="Repository owner or organization.")
    repo: str = Field(description="Repository name.")


async def get_codescanning_alerts(owner: str, repo: str) -> list[dict[str, Any]]:
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise RuntimeError("GITHUB_TOKEN environment variable is required")

    url = f"https://api.github.com/repos/{owner}/{repo}/code-scanning/alerts"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
    }
    params = {"state": "open", "per_page": PER_PAGE}

    alerts: list[dict[str, Any]] = []
    async with httpx.AsyncClient(headers=headers, timeout=httpx.Timeout(30.0)) as client:
        while True:
            response = await client.get(url, params=params)
            response.raise_for_status()

            alerts.extend(filter_codescanning_alerts(response.json()))

            next_url = get_next_link(response.headers.get("Link", ""))
            if not next_url:
                break

            url = next_url
            params = None

    return alerts


def filter_codescanning_alerts(alerts: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        alert
        for alert in alerts
        if alert.get("state") == "open"
        and (alert.get("rule") or {}).get("name")
        == LANGUAGE_SPECIFIC_PACKAGE_VULNERABILITY_RULE
    ]


async def normalize(alerts: Iterable[dict[str, Any]]) -> list[CodescanningAlert]:
    codescanningFindings: list[CodescanningAlert] = []

    for alert in alerts:
        codescanning_alert = CodescanningAlert.from_codescanning_alert(alert)
        if codescanning_alert is not None:
            codescanningFindings.append(codescanning_alert)

    return codescanningFindings


@tool(
    "collect_codescanning_alerts",
    args_schema=CodeScanningAlertInput,
)
async def codescanning_alerts_tool(owner: str, repo: str) -> list[dict[str, Any]]:
    """Collect open GitHub code scanning alerts for a repository."""
    alerts =  await get_codescanning_alerts(owner=owner, repo=repo)

    return await normalize(alerts)