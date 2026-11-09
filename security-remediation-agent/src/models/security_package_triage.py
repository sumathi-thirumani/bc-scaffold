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
    """Represent a root or intermediate package on an introducer path, with optional upgrade evidence."""
    package: str
    version: str
    classification: OccurrenceClassification = OccurrenceClassification.ROOT
    recommended_version: str | None = None
    requires_verification: bool = False
    recommendation_action: str | None = None

@dataclass
class TransistiveOccurances:
    """Describe one resolved package occurrence and the roots introducing it.

    Core idea: retain its manifest, version and full paths so remediation can target
    declared parents rather than trying to upgrade a transitive child directly."""
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


@dataclass
class CandidatePackage:
    """Track one proposed package version and its resolution outcome.

    An untested candidate is not verified. SUCCESS is assigned only after its
    proposed upgrade set resolves under the selected ecosystem policy."""
    package: str
    version: str
    isVerified: bool = False
    verification_status: str | None = None  # SUCCESS, FAILED
    verification_message: str | None = None  # Optional message providing details about the verification status


@dataclass
class PackageUpgradeRecommendation:
    """Carry upgrade evidence for a declared package or a transitive dependency parent.

    Core idea: normalize stable qualifying versions into ordered candidates and
    derive minimum/highest bounds. Initially prefer the lowest same-major option;
    review refines compatibility, while verification determines verified_version."""
    package: str
    from_version: str
    minimum_patched_version: str = ""
    highest_stable_version: str = ""
    compatible_version: str = ""
    source: Optional[str] = None
    pr_number: Optional[int] = None
    pull_url: Optional[str] = None
    pr_branch: Optional[str] = None
    qualifying_upgrade_versions: list[CandidatePackage] = field(default_factory=list)
    requires_verification: bool = False
    verified_version: str | None = None
    # Outcome of the compatible-version review: upgrade_found, no_upgrade,
    # excluded, not_declared or review_failed. None means no review has run.
    compatible_review_status: str | None = None

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
            # Resolvers hand over plain version strings; wrap them as candidates.
            candidate = raw if isinstance(raw, CandidatePackage) else CandidatePackage(self.package, str(raw))
            try:
                parsed = Version(candidate.version)
            except InvalidVersion:
                continue
            if parsed.is_prerelease or parsed.is_devrelease:
                continue
            if current is not None and parsed <= current:
                continue
            versions.setdefault(parsed, candidate)
        ordered = sorted(versions)
        self.qualifying_upgrade_versions = [versions[version] for version in ordered]
        self.minimum_patched_version = self.qualifying_upgrade_versions[0].version if ordered else ""
        self.highest_stable_version = self.qualifying_upgrade_versions[-1].version if ordered else ""
        self.compatible_version = next(
            (versions[version].version for version in ordered if current is not None and version.major == current.major),
            "",
        )

@dataclass
class SecurityPackageTriage:
    #Source: Vulnerability alert
    """Keep findings and remediation evidence for one ecosystem, package and manifest.

    Core idea: retain advisories alongside resolved occurrences, introducing parents,
    PR matches, recommendations and notes. Additional non-vulnerable updates use
    is_update so empty advisory fields are not presented as vulnerability data."""
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
    notes: str = ""
    is_update: bool = False
