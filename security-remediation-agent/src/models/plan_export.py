"""Compact export schema for remediation-plan.json.

The pipeline models carry everything later steps need; the exported file is a separate,
versioned contract. Transitive occurrences and their full paths are exported unchanged.
"""
from dataclasses import dataclass, field
from typing import Any

SCHEMA_VERSION = 1


@dataclass
class ExportVulnerability:
    number: int | None
    ghsa_id: str
    cve_id: str
    severity: str
    cvss: float | None
    vulnerable_range: str
    first_patched: str


@dataclass
class ExportAttempt:
    """A candidate version that was actually verified (or rejected), with its outcome."""
    version: str
    status: str | None
    message: str | None


@dataclass
class ExportRecommendation:
    package: str
    from_version: str
    minimum_patched_version: str
    compatible_version: str
    highest_stable_version: str
    verified_version: str | None
    compatible_review_status: str | None
    # Every qualifying version as a plain string; outcomes only for versions that were tried.
    candidates: list[str] = field(default_factory=list)
    verification: list[ExportAttempt] = field(default_factory=list)


@dataclass
class ExportPackage:
    package: str
    ecosystem: str
    manifest_path: str | None
    current_version: str
    severity: str
    is_update: bool
    istransitive: bool
    vulnerablility_version_range: str
    vulnerablility_fixed_version: str
    vulnerabilities: list[ExportVulnerability] = field(default_factory=list)
    recommendations: list[ExportRecommendation] = field(default_factory=list)
    transitive_dependency_occurrences: list[Any] = field(default_factory=list)
    scanning_alerts: list[Any] = field(default_factory=list)
    is_pull_available: bool = False
    pull_request_metadata: list[Any] = field(default_factory=list)
    notes: str = ""


@dataclass
class ExportBundle:
    ecosystem: str
    groupName: str
    severity: str
    action_type: Any
    packages: list[ExportPackage] = field(default_factory=list)


@dataclass
class PlanExport:
    schema_version: int
    summary: Any
    bundles: list[ExportBundle] = field(default_factory=list)


def _recommendation(recommendation) -> ExportRecommendation:
    candidates = recommendation.qualifying_upgrade_versions
    return ExportRecommendation(
        package=recommendation.package,
        from_version=recommendation.from_version,
        minimum_patched_version=recommendation.minimum_patched_version,
        compatible_version=recommendation.compatible_version,
        highest_stable_version=recommendation.highest_stable_version,
        verified_version=recommendation.verified_version,
        compatible_review_status=recommendation.compatible_review_status,
        candidates=[candidate.version for candidate in candidates],
        verification=[ExportAttempt(c.version, c.verification_status, c.verification_message)
                      for c in candidates if c.verification_status or c.verification_message],
    )


def _package(triage) -> ExportPackage:
    return ExportPackage(
        package=triage.package,
        ecosystem=triage.ecosystem,
        manifest_path=triage.manifest_path,
        current_version=triage.current_version,
        severity=triage.severity,
        is_update=triage.is_update,
        istransitive=triage.istransitive,
        vulnerablility_version_range=triage.vulnerablility_version_range,
        vulnerablility_fixed_version=triage.vulnerablility_fixed_version,
        vulnerabilities=[
            ExportVulnerability(v.number, v.ghsa_id, v.cve_id, v.severity, v.cvss,
                                v.vulnerable_range, v.first_patched)
            for v in triage.vulnerabilities],
        recommendations=[_recommendation(r) for r in triage.package_upgrade_recommendations],
        transitive_dependency_occurrences=triage.transitive_dependency_occurrences,
        scanning_alerts=triage.scanning_alerts,
        is_pull_available=triage.is_pull_available,
        pull_request_metadata=triage.pull_request_metadata,
        notes=triage.notes,
    )


def export_plan(plan) -> PlanExport:
    return PlanExport(
        schema_version=SCHEMA_VERSION,
        summary=plan.summary,
        bundles=[ExportBundle(b.ecosystem, b.groupName, b.severity, b.action_type,
                              [_package(t) for t in b.packages])
                 for b in plan.remediation_plan_bundles],
    )
