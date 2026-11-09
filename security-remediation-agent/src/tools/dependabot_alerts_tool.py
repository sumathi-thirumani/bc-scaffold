from collections.abc import Iterable
from typing import Any

import httpx
from langchain_core.tools import tool
from pydantic import BaseModel, Field

from ..models.gh.vulnerability_alert import VulnerabilityAlert
from ..models.security_remediation_constants import SecurityRemediationConstants
from .utils.github_api import (
    GITHUB_API_VERSION as GITHUB_API_VERSION,
    PER_PAGE,
    fetch_paginated_results,
    get_github_headers,
    get_next_link as get_next_link,
)

class DependabotAlertInput(BaseModel):
    """Validated input fields for collecting a repository's Dependabot alerts."""

    owner: str = Field(description="Repository owner or organization.")
    repo: str = Field(description="Repository name.")
    severities: list[str] | None = Field(
        default=None,
        description="Optional Dependabot severities: critical, high, medium (or moderate), low.",
    )

async def get_dependabot_alerts(
    owner: str,
    repo: str,
    severities: Iterable[str] | None = None,
) -> list[dict[str, Any]]:
    """Fetch open raw Dependabot alerts for a repository.

    ``severities`` is accepted for the collector interface but is not currently
    included in the API request; the shared helper follows GitHub pagination.
    """
    headers = get_github_headers()
    url = f"https://api.github.com/repos/{owner}/{repo}/dependabot/alerts"
    params = {
        "state": "open",
        "per_page": PER_PAGE,
    }
    return await fetch_paginated_results(
        url,
        params,
        headers=headers,
        owner=owner,
        repo=repo,
        resource="Dependabot alerts",
        client_factory=httpx.AsyncClient,
    )


async def normalize(alerts: Iterable[dict[str, Any]]) -> list[VulnerabilityAlert]:
    """Convert GitHub alert payloads into vulnerability models.

    Payloads without a package name are skipped because they cannot be grouped
    or resolved as dependency findings.
    """
    vulnerabilities: list[VulnerabilityAlert] = []

    for alert in alerts:
        vulnerability_alert = VulnerabilityAlert.from_dependabot_alert(alert)
        if vulnerability_alert is not None:
            vulnerabilities.append(vulnerability_alert)

    return vulnerabilities


@tool(
    "collect_dependabot_alerts",
    args_schema=DependabotAlertInput,
)
async def dependabot_alerts_tool(
    owner: str,
    repo: str,
    severities: list[str] | None = None,
) -> list[VulnerabilityAlert]:
    """Fetch open Dependabot alerts and return normalized vulnerability models.

    The tool keeps the raw API fetch separate from model conversion so each step
    can be tested and reused independently.
    """
    alerts = await get_dependabot_alerts(
        owner=owner,
        repo=repo,
        severities=severities,
    )
    return await normalize(alerts)
