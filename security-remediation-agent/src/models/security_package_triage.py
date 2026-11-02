from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from packaging.version import InvalidVersion, Version

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
    paths: list[list[TransistiveSourcePackage]] = field(default_factory=list)

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
    minimum_patched_version: str = ""
    highest_stable_version: str = ""
    compatible_version: str = ""
    source: Optional[str] = None
    pr_number: Optional[int] = None
    pull_url: Optional[str] = None
    pr_branch: Optional[str] = None
    qualifying_upgrade_versions: list[str] = field(default_factory=list)
    requires_verification: bool = False
    verified_version: str | None = None
    verification_status: str = "requires_validation"
    verification_method: str | None = None
    verification_notes: str = ""

    def __post_init__(self) -> None:
        """Derive bounds from stable qualifying upgrades, not all registry releases.

        compatible_version is the lowest qualifying upgrade in the current major.
        """
        versions = {}
        try:
            current = Version(self.from_version)
        except InvalidVersion:
            current = None
        for raw in self.qualifying_upgrade_versions:
            try:
                parsed = Version(raw)
            except InvalidVersion:
                continue
            if parsed.is_prerelease or parsed.is_devrelease:
                continue
            if current is not None and parsed <= current:
                continue
            versions.setdefault(parsed, raw)
        ordered = sorted(versions)
        self.qualifying_upgrade_versions = [versions[version] for version in ordered]
        self.minimum_patched_version = self.qualifying_upgrade_versions[0] if ordered else ""
        self.highest_stable_version = self.qualifying_upgrade_versions[-1] if ordered else ""
        self.compatible_version = next(
            (versions[version] for version in ordered if current is not None and version.major == current.major),
            "",
        )

@dataclass
class SecurityPackageTriage:
    #Source: Vulnerability alert
    package: str
    vulnerablility_version_range: str
    vulnerablility_fixed_version: str
    current_version: str = ""
    ecosystem: str = ""
    manifest_path: str | None = None
    #derivative information (highest severity)
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

