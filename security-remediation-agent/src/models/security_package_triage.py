from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from .gh.pull_request_metadata import PullRequestMetadata

from .gh.vulnerability_alert import VulnerabilityAlert


class OccurrenceClassification(str, Enum):
    """Where a resolved dependency occurrence sits in the manifest/lockfile graph."""
    ROOT = "root"                # declared directly in the manifest; no introducers
    TRANSITIVE = "transitive"    # pulled in by one or more introducer packages


@dataclass
class TransistiveSourcePackage:
    package: str
    version: str
    classification: OccurrenceClassification = OccurrenceClassification.ROOT
    recommended_version: str | None = None
    recommendation_source: str | None = None
    requires_verification: bool = False
    recommendation_action: str | None = None

@dataclass
class TransistiveOccurances:
    package: str
    version: str    
    introducers: list[TransistiveSourcePackage] = field(default_factory=list)
    classification: OccurrenceClassification = OccurrenceClassification.TRANSITIVE
    manifest_path: str | None = None

    def __post_init__(self) -> None:
        if not self.introducers:
            self.classification = OccurrenceClassification.ROOT


def occurrence_classification(occurrence) -> OccurrenceClassification:
    """Classification of a resolved occurrence: ROOT (declared directly in
    the manifest, no introducers) or TRANSITIVE (pulled in by another package)."""
    classification = occurrence.get("classification") if isinstance(occurrence, dict) else getattr(occurrence, "classification", None)
    if classification is not None:
        return classification
    introducers = occurrence.get("introducers") if isinstance(occurrence, dict) else getattr(occurrence, "introducers", None)
    return OccurrenceClassification.ROOT if not introducers else OccurrenceClassification.TRANSITIVE


def is_direct_occurrence(occurrence) -> bool:
    return occurrence_classification(occurrence) == OccurrenceClassification.ROOT


def is_direct_package(occurrences: list) -> bool:
    """A package is direct when it has no transitive occurrences at all,
    or every manifest lookup for it resolved as ROOT (no introducers)."""
    return not occurrences or all(is_direct_occurrence(o) for o in occurrences)

@dataclass
class PackageUpgradeRecommendation:
    package: str
    from_version: str
    to_version: str
    requires_verification: bool = False
    source: Optional[str] = None
    pr_number: Optional[int] = None
    pull_url: Optional[str] = None
    pr_branch: Optional[str] = None
    minimum_upgradable_version: str = ""
    candidate_versions: list[str] = field(default_factory=list)

@dataclass
class SecurityPackageTriage:
    #Source: Vulnerability alert
    package: str
    vulnerablility_version_range: str
    vulnerablility_fixed_version: str
    current_version: str = ""
    ecosystem: str = ""
    manifest_path: str | None = None
    #derivative information
    severity: str = ""

    #Source: Vulnerability alert and code scanning
    vulnerabilities: list[VulnerabilityAlert] = field(default_factory=list)
    scanning_alerts: list[Any] = field(default_factory=list)

    istransitive: bool = False    

    # component relationship    
    transitive_dependency_occurrences: list[TransistiveOccurances] = field(default_factory=list)
    package_upgrade_recommendations: list[PackageUpgradeRecommendation] = field(default_factory=list)

    #pulls - remediation & update consolidation
    is_pull_available: bool = False
    pull_request_metadata: list[PullRequestMetadata] = field(default_factory=list)

