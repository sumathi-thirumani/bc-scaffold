from dataclasses import dataclass, field
from enum import Enum

from .gh.pull_request_metadata import PullRequestMetadata
from .security_package_triage import SecurityPackageTriage
from .security_remediation_context import SecurityRemediationContext


class ActionType(str, Enum):
    MANUAL_ACTION = "Need manual/agent review"


@dataclass
class RemeditionPackageBundle:    
    ecosystem: str
    #Derived group name for the package bundle from renovate
    groupName: str
    # Severity of the issues in this package bundle (Max severity among the packages)
    severity: str
    packages: list[SecurityPackageTriage] = field(default_factory=list)
    action_type: ActionType | None = None  # Normnalize action type from packages


@dataclass
class RemediationReconcileInfo:
    ecosystem: str
    reconciliation_notes: str = ""


@dataclass
class RemediationPlan:
    # List of remediation plan bundles for this plan - Each bundle corresponds to an issue.
    remediation_plan_bundles: list[RemeditionPackageBundle] = field(default_factory=list)
    #reconciliation_info: list[RemediationReconcileInfo] = field(default_factory=list)
    summary: SecurityRemediationContext | None = None
