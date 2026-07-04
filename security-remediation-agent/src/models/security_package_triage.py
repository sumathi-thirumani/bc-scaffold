from dataclasses import dataclass, field
from typing import Any

from ..tools.github_pr_collector.model.pull_request_metadata import PullRequestMetadata
from ..tools.github_vulnerability_collector.model.vulnerability_alert import VulnerabilityAlert


@dataclass
class SecurityPackageTriage:
    #Source: Vulnerability alert
    package: str
    current_version_range: str
    remediated_version: str
    ecosystem: str = ""
    severity: str = ""

    #Source: Vulnerability alert and code scanning
    vulnerabilities: list[VulnerabilityAlert] = field(default_factory=list)
    scanning_alerts: list[Any] = field(default_factory=list)

    # sbom
    istransitive: bool = False
    transitive_source_package: list[str] = field(default_factory=list)
    installed_version: str = ""
    fixed_version: str = ""
    manifest_path: str = ""
    lockfile_path: str = ""
    dependency_path: list[str] = field(default_factory=list)
    nearest_declared_parent: str = ""
    remediation_target_dependency: str = ""
    graph_confidence: str = "unavailable"
    graph_status: str = "dependency graph unavailable"
    override_used: bool = False
    override_justification: str = ""


    #pulls - remediation by bot
    is_pull_available: bool = False
    pull_metadata: list[PullRequestMetadata] = field(default_factory=list)

    # Determined values
    #Computed; get the least applicable patch. if its breaking version. populate breaking; else non-breaking.
    # for scenarios where both breaking and non-breaking present; both are populated.
    breaking_upgrade_version: str = ""
    non_breaking_upgrade_version: str = ""
    breaking_pull_available: bool = False
    breaking_pull_metadata: PullRequestMetadata | None = None
    non_breaking_pull_available: bool = False
    non_breaking_pull_metadata: PullRequestMetadata | None = None
    isbreakable: bool = False

    #issue
    is_issue_created: bool = False
    issue_metadata: dict[str, Any] = field(default_factory=dict)

    #pulls - upgrades by bot
    isupgradable: bool = False
    upgrade_version: str = ""
    upgrade_pull_metadata: list[PullRequestMetadata] = field(default_factory=list)
    

    @property
    def relationship(self) -> str:
        """Derived from ``istransitive`` so serialization is always consistent.

        Downstream code (e.g. the remediation planner) serializes this property
        into ``package.relationship`` in the orchestrator output.  Keeping it as
        a computed property means it can never drift out of sync with the
        underlying ``istransitive`` flag.
        """
        return "transitive" if self.istransitive else "direct"