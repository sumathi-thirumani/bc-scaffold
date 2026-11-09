from dataclasses import dataclass, field
from typing import Any

from ...engines.resolvers.artifact_pr_resolver.pr_pattern_version_extractor import get_version_bumps
from .version_bump import VersionBump

__all__ = ["PullRequestMetadata", "VersionBump", "build_pull_request_metadata"]


@dataclass
class PullRequestMetadata:
    """Keep bot PR identity and parsed package transitions together for remediation matching."""
    pr_number: int | None = None
    pr_title: str = ""
    pr_branch: str = ""
    pull_url: str = ""
    version_bumps: list[VersionBump] = field(default_factory=list)
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
            pr_title=pull_request.get("title") or "",
            pr_branch=(pull_request.get("head") or {}).get("ref") or "",
            pull_url=pull_request.get("html_url") or "",
            version_bumps=version_bumps,
            author=(pull_request.get("user") or {}).get("login") or "",
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
            user.get("login") or "",
            pull_request.get("title") or "",
            pull_request.get("body") or "",
        ),
    )
