from collections.abc import Iterable
from typing import Any

from pydantic import BaseModel

from ..utils.version_bump_resolver import VersionBump, get_version_bumps


class PullRequestMetadata(BaseModel):
    pr_number: int | None = None
    pr_title: str = ""
    pr_branch: str = ""
    pull_url: str = ""

    version_bumps: list[VersionBump]

    severity: str = ""
    author: str = ""

    @classmethod
    def from_pull_request(
        cls,
        pull_request: dict[str, Any],
        version_bumps: list[VersionBump],
    ) -> "PullRequestMetadata":
        return cls(
            pr_number=pull_request.get("number"),
            pr_title=pull_request.get("title", ""),
            pr_branch=(pull_request.get("head") or {}).get("ref", ""),
            pull_url=pull_request.get("html_url", ""),
            version_bumps=version_bumps,
            author=(pull_request.get("user") or {}).get("login", ""),
        )


def is_bot_owner(user: str) -> bool:
    return "[bot]" in user.lower()


def build_pull_request_metadata(
    owner: str,
    repo: str,
    pull_requests: Iterable[dict[str, Any]],
) -> list[PullRequestMetadata]:
    """
    Convert GitHub pull requests into normalized PullRequestMetadata objects.
    """

    results: list[PullRequestMetadata] = []

    for pull_request in pull_requests:
        user = pull_request.get("user") or {}

        if not is_bot_owner(user.get("login", "")):
            continue

        if not pull_request.get("number"):
            continue

        results.append(
            PullRequestMetadata.from_pull_request(
                pull_request=pull_request,
                version_bumps=get_version_bumps(
                    pull_request.get("title", ""),
                    pull_request.get("body", ""),
                ),
            )
        )

    return results