import logging
import os
import re
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

import httpx

GITHUB_API_VERSION = "2022-11-28"
PER_PAGE = 100
NEXT_LINK_PATTERN = re.compile(r'<([^>]+)>;\s*rel="next"')
GITHUB_API_TIMEOUT = httpx.Timeout(
    connect=10.0,
    read=30.0,
    write=10.0,
    pool=10.0,
)

logger = logging.getLogger(__name__)


class GitHubApiError(RuntimeError):
    """Preserve GitHub request failure context and optional HTTP status for callers."""
    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        self.status_code = status_code
        super().__init__(message)


def _auth_hint(status_code: int) -> str:
    if status_code == 401:
        return (
            ": GITHUB_TOKEN is invalid, expired or revoked. Set a valid token, for example "
            "$env:GITHUB_TOKEN = (gh auth token)"
        )
    if status_code == 403:
        return (
            ": access denied or rate limited. Check the token's repo/security_events scopes, "
            "SSO authorization and rate limits"
        )
    return ""


def get_github_headers() -> dict[str, str]:
    """Build authenticated GitHub API headers."""
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        logger.error("Cannot call GitHub API: GITHUB_TOKEN is not configured")
        raise RuntimeError("GITHUB_TOKEN environment variable is required")

    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
    }


def get_next_link(link_header: str) -> str | None:
    match = NEXT_LINK_PATTERN.search(link_header)
    return match.group(1) if match else None


def is_github_api_url(url: str) -> bool:
    try:
        parsed_url = urlsplit(url)
        return (
            parsed_url.scheme == "https"
            and parsed_url.hostname == "api.github.com"
            and parsed_url.username is None
            and parsed_url.password is None
            and parsed_url.port in (None, 443)
        )
    except ValueError:
        return False


async def fetch_paginated_results(
    url: str,
    params: dict[str, Any] | None,
    *,
    headers: dict[str, str],
    owner: str,
    repo: str,
    resource: str,
    client_factory: Callable[..., httpx.AsyncClient],
) -> list[dict[str, Any]]:
    """Fetch all pages of a GitHub list endpoint using shared auth and safety rules."""
    started_at = time.perf_counter()
    logger.info("Fetching %s for %s/%s", resource, owner, repo)
    results: list[dict[str, Any]] = []

    async with client_factory(
        headers=headers,
        timeout=GITHUB_API_TIMEOUT,
    ) as client:
        page = 0
        while True:
            page += 1
            request_started_at = time.perf_counter()
            logger.debug("Requesting %s page %d for %s/%s", resource, page, owner, repo)
            try:
                response = await client.get(url, params=params)
            except httpx.HTTPError as exc:
                logger.exception(
                    "GitHub request failed for %s/%s %s page %d after %.3f seconds",
                    owner,
                    repo,
                    resource,
                    page,
                    time.perf_counter() - request_started_at,
                )
                raise GitHubApiError(
                    f"GitHub request failed for {resource} on page {page}"
                ) from exc

            try:
                response.raise_for_status()
            except httpx.HTTPStatusError as exc:
                logger.error(
                    "GitHub returned HTTP %d for %s/%s %s page %d",
                    response.status_code,
                    owner,
                    repo,
                    resource,
                    page,
                )
                raise GitHubApiError(
                    f"GitHub request for {resource} failed with HTTP {response.status_code}"
                    f"{_auth_hint(response.status_code)}",
                    status_code=response.status_code,
                ) from exc

            try:
                data = response.json()
            except ValueError as exc:
                logger.exception(
                    "GitHub returned invalid JSON for %s/%s %s page %d",
                    owner,
                    repo,
                    resource,
                    page,
                )
                raise GitHubApiError(
                    f"GitHub returned invalid JSON for {resource} on page {page}"
                ) from exc

            if not isinstance(data, list) or any(not isinstance(item, dict) for item in data):
                logger.error(
                    "GitHub returned an unexpected payload for %s/%s %s page %d",
                    owner,
                    repo,
                    resource,
                    page,
                )
                raise GitHubApiError(
                    f"GitHub returned an unexpected payload for {resource} on page {page}"
                )

            results.extend(data)
            logger.debug(
                "Fetched %d %s from page %d for %s/%s (HTTP %d) in %.3f seconds",
                len(data),
                resource,
                page,
                owner,
                repo,
                response.status_code,
                time.perf_counter() - request_started_at,
            )

            next_url = get_next_link(response.headers.get("Link", ""))
            if not next_url:
                break

            if not is_github_api_url(next_url):
                logger.error(
                    "Rejected untrusted pagination URL for %s/%s %s after page %d",
                    owner,
                    repo,
                    resource,
                    page,
                )
                raise GitHubApiError(
                    f"GitHub returned an invalid pagination URL for {resource}"
                )

            url = next_url
            params = None

    logger.info(
        "Fetched %d %s across %d page(s) for %s/%s in %.3f seconds",
        len(results),
        resource,
        page,
        owner,
        repo,
        time.perf_counter() - started_at,
    )
    return results
