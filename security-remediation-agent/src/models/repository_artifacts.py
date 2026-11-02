from dataclasses import dataclass, field

from ..tools.ecosystem_manifest_tool import ManifestTool
from .gh.pull_request_metadata import PullRequestMetadata


@dataclass
class RepositoryArtifacts:
    """Repository data gathered once per run and shared by downstream agents.

    ``manifest_tool`` carries the run-scoped manifest cache; manifests named by
    the findings are already prefetched into it.
    """

    owner: str
    repo: str
    pull_requests: list[PullRequestMetadata] = field(default_factory=list)
    manifest_tool: ManifestTool = field(default_factory=ManifestTool, repr=False)
    ref: str | None = None
