"""Default grouping: bundle findings by ecosystem and upgrade type when no Renovate config applies."""
from packaging.version import InvalidVersion, Version

from ...models.remediation_plan import RemeditionPackageBundle
from ...models.security_package_triage import SecurityPackageTriage

UPGRADE_ORDER = {"major": 0, "minor": 1, "patch": 2, "unknown": 3}
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


class DefaultGroupingEngine:
    """Group triage items by ecosystem and upgrade type."""

    @staticmethod
    def version_upgrade_type(current: str, target: str) -> str:
        """Classify a newer version by its largest changed release component."""
        try:
            before = Version((current or "").lstrip("vV"))
            after = Version((target or "").lstrip("vV"))
        except InvalidVersion:
            return "unknown"
        if after <= before:
            return "unknown"
        if after.major != before.major:
            return "major"
        if after.minor != before.minor:
            return "minor"
        return "patch"

    @classmethod
    def upgrade_type(cls, package: SecurityPackageTriage) -> str:
        """Use parent upgrade versions for transitive findings, not the child's fix."""
        if not package.istransitive:
            return cls.version_upgrade_type(package.current_version, package.vulnerablility_fixed_version)
        kinds = [cls.version_upgrade_type(rec.from_version, rec.minimum_patched_version)
                 for rec in package.package_upgrade_recommendations]
        return min(kinds, key=UPGRADE_ORDER.__getitem__) if kinds else "unknown"

    @staticmethod
    def bundle_severity(packages: list[SecurityPackageTriage]) -> str:
        return max((package.severity.lower() for package in packages),
                   key=lambda severity: SEVERITY_ORDER.get(severity, 0), default="unknown") or "unknown"

    @classmethod
    def group_packages(cls, triage_items: list[SecurityPackageTriage]) -> list[RemeditionPackageBundle]:
        grouped: dict[tuple[str, str], list[SecurityPackageTriage]] = {}
        for package in triage_items:
            key = (package.ecosystem.lower() or "unknown", cls.upgrade_type(package))
            grouped.setdefault(key, []).append(package)
        return [RemeditionPackageBundle(
            ecosystem=ecosystem, groupName="default" if kind == "unknown" else f"{ecosystem}/{kind}",
            severity=cls.bundle_severity(grouped[(ecosystem, kind)]),
            packages=sorted(grouped[(ecosystem, kind)],
                            key=lambda item: (item.package.casefold(), item.manifest_path or "")),
        ) for ecosystem, kind in sorted(grouped, key=lambda key: (key[0], UPGRADE_ORDER[key[1]]))]
