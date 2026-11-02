import asyncio
import logging
from typing import Any

import httpx
from langchain_core.tools import tool
from pydantic import BaseModel, Field

from ..engines.resolvers.artifact_pr_resolver.pr_review_version_extractor import extract_version_changes
from ..models.gh.pull_request_metadata import (
    PullRequestMetadata,
    VersionBump,
    build_pull_request_metadata,
)
from .utils.github_api import (
    GITHUB_API_TIMEOUT,
    GITHUB_API_VERSION as GITHUB_API_VERSION,
    GitHubApiError,
    PER_PAGE,
    fetch_paginated_results,
    get_github_headers,
    get_next_link as get_next_link,
    is_github_api_url as is_github_api_url,
)

GitHubObject = dict[str, Any]

logger = logging.getLogger(__name__)


def _normalize_version_bumps(
    pattern_bumps: list[VersionBump],
    review_bumps: list[VersionBump],
) -> list[VersionBump]:
    """Prefer review evidence per package and deduplicate normalized transitions."""
    review_packages = {bump.package.strip().casefold() for bump in review_bumps}
    candidates = [
        *review_bumps,
        *(bump for bump in pattern_bumps if bump.package.strip().casefold() not in review_packages),
    ]
    results: list[VersionBump] = []
    seen: set[tuple[str, str, str]] = set()
    for bump in candidates:
        normalized = VersionBump(
            package=bump.package.strip(),
            from_version=bump.from_version.strip(),
            to_version=bump.to_version.strip(),
        )
        key = (
            normalized.package.casefold(),
            normalized.from_version,
            normalized.to_version,
        )
        if key not in seen:
            seen.add(key)
            results.append(normalized)
    return results


class SecurityDependencyPullRequestInput(BaseModel):
    """Input schema for collecting pull requests related to dependency security fixes."""

    owner: str = Field(description="Repository owner or organization.")
    repo: str = Field(description="Repository name.")
    enable_dependency_review: bool = Field(default=False, description="Enable dependency-review API requests; temporarily disabled by default.")
    review_all: bool = Field(default=False, description="Use dependency-review evidence even when bot text provides version transitions.")


async def get_open_pull_requests(owner: str, repo: str) -> list[GitHubObject]:
    """Fetch all open pull requests from a GitHub repository."""
    url = f"https://api.github.com/repos/{owner}/{repo}/pulls"
    params = {"state": "open", "per_page": PER_PAGE}
    return await fetch_paginated_results(
        url,
        params,
        headers=get_github_headers(),
        owner=owner,
        repo=repo,
        resource="open pull requests",
        client_factory=httpx.AsyncClient,
    )


@tool(
    "collect_security_dependency_pull_requests",
    args_schema=SecurityDependencyPullRequestInput,
)
async def pull_requests_tool(
    owner: str,
    repo: str,
    review_all: bool = False,
    enable_dependency_review: bool = False,
) -> list[PullRequestMetadata]:
    """Collect bot PRs using pattern parsing and dependency-review version changes.

    Dependency-review API calls are disabled by default. When explicitly enabled,
    unambiguous bot-text transitions avoid dependency-review calls. Unparsed or
    conflicting transitions use bounded API requests with a shared client and PR SHAs.
    If review fails, retain pattern evidence and log a warning.
    """
    logger.info("Collecting dependency-security pull requests for %s/%s", owner, repo)
    if not enable_dependency_review:
        logger.info("Dependency-review API disabled; extracting PR versions from title/body only")
    pull_requests = await get_open_pull_requests(owner=owner, repo=repo)
    metadata_list: list[PullRequestMetadata] = []
    missing_number = 0
    non_bot_author = 0
    without_version_bumps = 0
    pending_reviews = []
    for pull_request in pull_requests:
        if not pull_request.get("number"):
            missing_number += 1
            continue

        user_ = (pull_request.get("user") or {}).get("login") or ""
        if "bot" not in user_.lower():
            non_bot_author += 1
            continue

        metadata = build_pull_request_metadata(
            owner=owner,
            repo=repo,
            pull_request=pull_request,
        )
        if metadata is not None:
            pattern_bumps = metadata.version_bumps
            # One stable transition per package can be taken directly from bot text.
            # Conflicting transitions and unparsed group updates need API evidence.
            grouped = {}
            for bump in pattern_bumps:
                grouped.setdefault(bump.package.strip().casefold(), set()).add(
                    (bump.from_version.strip(), bump.to_version.strip()))
            if enable_dependency_review and (review_all or not pattern_bumps or any(len(values) != 1 for values in grouped.values())):
                pending_reviews.append((pull_request, metadata))
            else:
                metadata.version_bumps = _normalize_version_bumps(pattern_bumps, [])
            metadata_list.append(metadata)
            if not metadata.version_bumps:
                without_version_bumps += 1
            logger.debug(
                "Accepted pull request #%s by %s with %d version bump(s)",
                metadata.pr_number,
                metadata.author,
                len(metadata.version_bumps),
            )

    if pending_reviews:
        semaphore = asyncio.Semaphore(4)
        # httpx.Client may be shared by the bounded worker threads.
        with httpx.Client(headers=get_github_headers(), timeout=GITHUB_API_TIMEOUT) as client:
            async def review_one(pr, metadata):
                async with semaphore:
                    try:
                        bumps = await asyncio.to_thread(
                            extract_version_changes, owner, repo, pr["number"],
                            pull_request=pr, client=client,
                        )
                    except GitHubApiError as exc:
                        logger.warning("Dependency review failed for %s/%s#%s; retaining %d pattern bump(s): %s",
                                       owner, repo, metadata.pr_number, len(metadata.version_bumps), exc)
                        return
                    metadata.version_bumps = _normalize_version_bumps(metadata.version_bumps, bumps)
            # Wait for every worker before closing the shared client, including failures.
            results = await asyncio.gather(*(review_one(pr, metadata) for pr, metadata in pending_reviews),
                                           return_exceptions=True)
            for result in results:
                if isinstance(result, BaseException):
                    raise result
    without_version_bumps = sum(not metadata.version_bumps for metadata in metadata_list)
    logger.info("Dependency-review API required for %d of %d retained bot PRs",
                len(pending_reviews), len(metadata_list))

    logger.info(
        "Processed %d open pull requests for %s/%s: retained %d bot PR(s), "
        "%d retained PR(s) had no parsed version bumps; skipped %d without a number "
        "and %d non-bot PR(s)",
        len(pull_requests),
        owner,
        repo,
        len(metadata_list),
        without_version_bumps,
        missing_number,
        non_bot_author,
    )
    return metadata_list


security_dependency_pull_requests_tool = pull_requests_tool
