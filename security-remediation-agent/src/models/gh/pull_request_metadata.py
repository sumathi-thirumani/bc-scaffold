from dataclasses import dataclass, field
import logging
from typing import Any

from ...tools.utils.version_bump_resolver import VersionBump, get_version_bumps

@dataclass
class PullRequestMetadata:
    pr_number: int | None = None
    pr_title: str = ""
    pr_branch: str = ""
    pull_url: str = ""
    version_bumps: list[VersionBump] = field(default_factory=list)
    mergeable_state: str = ""
    author: str = ""

    def __getitem__(self, key: str) -> Any:
        return self.model_dump()[key]

    def model_dump(self) -> dict[str, Any]:
        return {
            "pr_number": self.pr_number,
            "pr_title": self.pr_title,
            "pr_branch": self.pr_branch,
            "pull_url": self.pull_url,
            "version_bumps": [
                bump.model_dump() if hasattr(bump, "model_dump") else bump
                for bump in self.version_bumps
            ],
            "severity": "",
            "author": self.author,
        }

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
            mergeable_state=pull_request.get("mergeable_state", ""),
            author=(pull_request.get("user") or {}).get("login", ""),
        )


def build_pull_request_metadata(
    owner: str,
    repo: str,
    pull_request: dict[str, Any],
) -> PullRequestMetadata | None:
    """
    Convert GitHub pull requests into normalized PullRequestMetadata objects.
    """

    user = pull_request.get("user") or {}

    if not pull_request.get("number"):
        return None

    return PullRequestMetadata.from_pull_request(
        pull_request=pull_request,
        version_bumps=get_version_bumps(
            user.get("login", ""),
            pull_request.get("title", ""),
            pull_request.get("body", ""),
        ),
        
    )