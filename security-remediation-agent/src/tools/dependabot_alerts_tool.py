from collections.abc import Iterable
from typing import Any

import httpx
from langchain_core.tools import tool
from pydantic import BaseModel, Field, field_validator

from ..models.gh.vulnerability_alert import VulnerabilityAlert
from ..models.security_remediation_constants import SecurityRemediationConstants
from .utils.github_api import (
    GITHUB_API_VERSION as GITHUB_API_VERSION,
    PER_PAGE,
    fetch_paginated_results,
    get_github_headers,
    get_next_link as get_next_link,
)

DEFAULT_SEVERITIES = SecurityRemediationConstants.DEFAULT_SEVERITIES


def normalize_severity(severity: str) -> str:
    value = severity.strip().lower()
    return "medium" if value == "moderate" else value


class DependabotAlertInput(BaseModel):
    owner: str = Field(description="Repository owner or organization.")
    repo: str = Field(description="Repository name.")
    severities: list[str] | None = Field(
        default=None,
        description="Optional Dependabot severities: critical, high, medium (or moderate), low.",
    )

    @field_validator("severities")
    @classmethod
    def validate_severities(cls, severities: list[str] | None) -> list[str] | None:
        if severities is None:
            return severities

        normalized = [normalize_severity(severity) for severity in severities]
        invalid_severities = set(normalized) - DEFAULT_SEVERITIES
        if invalid_severities:
            valid_values = ", ".join(sorted(DEFAULT_SEVERITIES))
            invalid_values = ", ".join(sorted(invalid_severities))
            raise ValueError(
                f"Unsupported Dependabot severity values: {invalid_values}. "
                f"Expected one or more of: {valid_values}."
            )

        return normalized


async def get_dependabot_alerts(
    owner: str,
    repo: str,
    severities: Iterable[str] | None = None,
) -> list[dict[str, Any]]:
    headers = get_github_headers()
    severity_filter = {normalize_severity(value) for value in (severities or DEFAULT_SEVERITIES)}
    invalid_severities = severity_filter - DEFAULT_SEVERITIES
    if invalid_severities:
        valid_values = ", ".join(sorted(DEFAULT_SEVERITIES))
        invalid_values = ", ".join(sorted(invalid_severities))
        raise ValueError(
            f"Unsupported Dependabot severity values: {invalid_values}. "
            f"Expected one or more of: {valid_values}."
        )

    url = f"https://api.github.com/repos/{owner}/{repo}/dependabot/alerts"
    params = {
        "state": "open",
        "severity": ",".join(sorted(severity_filter)),
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
    """Collect and normalize open GitHub Dependabot alerts for a repository."""
    alerts = await get_dependabot_alerts(
        owner=owner,
        repo=repo,
        severities=severities,
    )
    return await normalize(alerts)
