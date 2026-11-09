from dataclasses import dataclass, field
from enum import Enum

from .gh.pull_request_metadata import PullRequestMetadata
from .security_package_triage import SecurityPackageTriage
from .security_remediation_context import SecurityRemediationContext


class ActionType(str, Enum):
    """Describe the downstream action requested for a remediation bundle."""
    MANUAL_ACTION = "Need manual/agent review"


@dataclass
class RemeditionPackageBundle:    
    """Keep findings sharing an ecosystem and remediation group together.

    A bundle is a planning/reporting unit. Verification still combines upgrades
    across bundles when they modify the same declaration manifest."""
    ecosystem: str
    #Derived group name for the package bundle from renovate
    groupName: str
    # Severity of the issues in this package bundle (Max severity among the packages)
    severity: str
    packages: list[SecurityPackageTriage] = field(default_factory=list)
    action_type: ActionType | None = None  # Normnalize action type from packages


@dataclass
class RemediationPlan:
    # List of remediation plan bundles for this plan - Each bundle corresponds to an issue.
    """Carry grouped findings and run summary through verification and reporting.

    Packages retain their evidence and recommendation outcomes so unresolved
    findings remain visible even when no verified Renovate rule can be generated."""
    remediation_plan_bundles: list[RemeditionPackageBundle] = field(default_factory=list)
    summary: SecurityRemediationContext | None = None
