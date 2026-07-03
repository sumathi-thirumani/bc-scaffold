import os
from typing import Any

import httpx
from langchain_core.tools import tool
from pydantic import BaseModel, Field

from ..github_vulnerability_collector.dependabot_alerts_tool import (
    GITHUB_API_VERSION,
    PER_PAGE,
    get_next_link,
)
from .model.pull_request_metadata import PullRequestMetadata, build_pull_request_metadata

GitHubObject = dict[str, Any]


class SecurityDependencyPullRequestInput(BaseModel):
    """
    Input schema for collecting pull requests related to dependency security fixes.
    """

    owner: str = Field(description="Repository owner or organization.")
    repo: str = Field(description="Repository name.")


def get_github_headers() -> dict[str, str]:
    """
    Build authenticated GitHub API headers.
    """
    token = os.environ.get("GITHUB_TOKEN")

    if not token:
        raise RuntimeError("GITHUB_TOKEN environment variable is required")

    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
    }


async def get_open_pull_requests(owner: str, repo: str) -> list[GitHubObject]:
    """
    Fetch all open pull requests from a GitHub repository.
    """

    url = f"https://api.github.com/repos/{owner}/{repo}/pulls"

    params: dict[str, Any] | None = {
        "state": "open",
        "per_page": PER_PAGE,
    }

    pull_requests: list[GitHubObject] = []

    timeout = httpx.Timeout(
        connect=10.0,
        read=30.0,
        write=10.0,
        pool=10.0,
    )

    async with httpx.AsyncClient(
        headers=get_github_headers(),
        timeout=timeout,
    ) as client:

        while True:
            response = await client.get(url, params=params)

            try:
                response.raise_for_status()
            except httpx.HTTPStatusError as exc:
                raise RuntimeError(
                    "GitHub API request failed: "
                    f"{response.status_code} {response.text}"
                ) from exc

            data: list[GitHubObject] = response.json()
            pull_requests.extend(data)

            next_url = get_next_link(response.headers.get("Link", ""))

            if not next_url:
                break

            url = next_url
            params = None  # pagination already includes params

    return pull_requests


@tool(
    "collect_security_dependency_pull_requests",
    args_schema=SecurityDependencyPullRequestInput,
)
async def pull_requests_tool(
    owner: str,
    repo: str,
) -> list[PullRequestMetadata]:
    """
    Collect open dependency security pull requests.
    """

    pull_requests = await get_open_pull_requests(
        owner=owner,
        repo=repo,
    )

    return build_pull_request_metadata(
        owner=owner,
        repo=repo,
        pull_requests=pull_requests,
    )


security_dependency_pull_requests_tool = pull_requests_tool