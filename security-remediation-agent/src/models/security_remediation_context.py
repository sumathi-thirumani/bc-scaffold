
from dataclasses import dataclass, field

@dataclass
class VulnerabilitySummary:
    """Count normalized vulnerability severities for the run summary."""
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    others: int = 0

@dataclass
class SecurityRemediationContext:
    """Accumulate collection and remediation totals for the pipeline and final report."""
    total_vulnerabilities: int = 0
    total_code_scanning_alerts: int = 0
    total_reviewed_prs: int = 0
    total_ignored_prs: int = 0
    total_remediation_prs: int = 0
    vulnerabilities_summary: VulnerabilitySummary = field(default_factory=VulnerabilitySummary)

@dataclass
class RepositoryContext:
    """Carry repository identity, selected ref and discovered security-feature state.

    The ref selects files throughout the run; callers may override the repository
    default branch without changing its ownership or feature metadata."""
    owner: str
    repo: str
    description: str = ""
    ref: str = "main"
    isPrivate: bool = False
    dependabotEnabled: bool = False
    codeScanningEnabled: bool = False
    renovateIntegrationEnabled: bool = False
    security_remediation_context: SecurityRemediationContext = field(default_factory=SecurityRemediationContext)
