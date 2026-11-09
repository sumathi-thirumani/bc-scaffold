"""Group triaged findings into remediation bundles without losing their evidence."""
import logging
from pathlib import PurePosixPath

from packaging.version import InvalidVersion, Version

from ..engines.remediation_grouping_engine import RemediationGroupingEngine
from ..models.remediation_plan import RemediationPlan, RemeditionPackageBundle
from ..models.security_package_triage import SecurityPackageTriage
from ..models.security_remediation_context import SecurityRemediationContext
from ..tools.ecosystem_manifest_tool import ManifestTool

logger = logging.getLogger(__name__)
UPGRADE_ORDER = {"major": 0, "minor": 1, "patch": 2, "unknown": 3}
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


class RemediationPlannerAgent:
    """Turn reviewed triage findings into remediation bundles and upgrade targets.

    Core idea: apply repository Renovate groups, or ecosystem/upgrade-type defaults,
    then consolidate shared parents within each manifest using common qualifying
    versions and reviewed compatibility limits. Verification runs after planning."""
    def __init__(self, manifest_tool: ManifestTool | None = None) -> None:
        self.manifest_tool = manifest_tool

    @staticmethod
    def _version_upgrade_type(current: str, target: str) -> str:
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
    def _upgrade_type(cls, package: SecurityPackageTriage) -> str:
        """Use parent upgrade versions for transitive findings, not the child's fix."""
        if not package.istransitive:
            return cls._version_upgrade_type(package.current_version, package.vulnerablility_fixed_version)
        kinds = [cls._version_upgrade_type(rec.from_version, rec.minimum_patched_version)
                 for rec in package.package_upgrade_recommendations]
        return min(kinds, key=UPGRADE_ORDER.__getitem__) if kinds else "unknown"

    @staticmethod
    def _bundle_severity(packages: list[SecurityPackageTriage]) -> str:
        return max((package.severity.lower() for package in packages),
                   key=lambda severity: SEVERITY_ORDER.get(severity, 0), default="unknown") or "unknown"

    @classmethod
    def _build_remediation_package_bundles_by_ecosystem(
        cls, triage_items: list[SecurityPackageTriage],
    ) -> list[RemeditionPackageBundle]:
        """Group by ecosystem and upgrade type when no Renovate configuration is available."""
        grouped: dict[tuple[str, str], list[SecurityPackageTriage]] = {}
        for package in triage_items:
            key = (package.ecosystem.lower() or "unknown", cls._upgrade_type(package))
            grouped.setdefault(key, []).append(package)
        return [RemeditionPackageBundle(
            ecosystem=ecosystem, groupName="default" if kind == "unknown" else f"{ecosystem}/{kind}",
            severity=cls._bundle_severity(grouped[(ecosystem, kind)]),
            packages=sorted(grouped[(ecosystem, kind)],
                            key=lambda item: (item.package.casefold(), item.manifest_path or "")),
        ) for ecosystem, kind in sorted(grouped, key=lambda key: (key[0], UPGRADE_ORDER[key[1]]))]

    async def _build_remediation_package_bundles(
        self, triage_items: list[SecurityPackageTriage], repo: dict | None,
        ref: str | None = None,
    ) -> list[RemeditionPackageBundle]:
        owner = (repo or {}).get("owner")
        name = (repo or {}).get("repo") or (repo or {}).get("name")
        if owner and name:
            try:
                bundles = await RemediationGroupingEngine.group_packages_from_github(
                    triage_items, owner, name, ref, manifest_tool=self.manifest_tool)
                if bundles is not None:
                    for bundle in bundles:
                        bundle.severity = self._bundle_severity(bundle.packages)
                    return bundles
            except Exception as exc:
                logger.warning("Cannot group by Renovate config for %s/%s; using fallback: %s",
                               owner, name, exc)
        return self._build_remediation_package_bundles_by_ecosystem(triage_items)

    async def plan(
        self, triage_items: list[SecurityPackageTriage], context: SecurityRemediationContext,
        repo: dict | None = None, ref: str | None = None,
    ) -> RemediationPlan:
        """Group reviewed triage items, derive shared upgrade targets, and retain the run summary."""
        logger.info("Planning remediation for %d triage items", len(triage_items))
        bundles = await self._build_remediation_package_bundles(triage_items, repo, ref)
        remediation_plan = RemediationPlan(
            remediation_plan_bundles=bundles,
            summary=context,
        )
        self.populate_upgrade_targets(remediation_plan)
        return remediation_plan

    @classmethod
    def populate_upgrade_targets(cls, remediation_plan: RemediationPlan) -> None:
        """Rebuild consolidated targets from the current recommendations in each bundle."""
        for bundle in remediation_plan.remediation_plan_bundles:
            bundle.upgrade_targets = cls._build_upgrade_targets(bundle.packages)

    @staticmethod
    def _build_upgrade_targets(packages: list[SecurityPackageTriage]) -> list[dict]:
        grouped = {}
        for package in packages:
            manifest_path = (
                PurePosixPath(package.manifest_path.replace("\\", "/").lstrip("/")).as_posix()
                if package.manifest_path else None
            )
            entries = [
                {"package": recommendation.package, "current_version": recommendation.from_version,
                 "minimum_fixed_version": recommendation.minimum_patched_version,
                 "compatible_version": recommendation.compatible_version,
                 "review_status": recommendation.compatible_review_status,
                 "highest_fixed_version": recommendation.highest_stable_version,
                 "qualifying_versions": [c.version for c in recommendation.qualifying_upgrade_versions]}
                for recommendation in package.package_upgrade_recommendations
            ]
            if not entries and not package.istransitive:
                entries = [{"package": package.package, "current_version": package.current_version,
                            "minimum_fixed_version": package.vulnerablility_fixed_version,
                            "compatible_version": "", "highest_fixed_version": "",
                            "qualifying_versions": None}]
            if not entries:
                entries = [
                    {"package": parent.package, "current_version": parent.version,
                     "minimum_fixed_version": "", "compatible_version": "",
                     "highest_fixed_version": "", "qualifying_versions": []}
                    for occurrence in package.transitive_dependency_occurrences
                    for parent in occurrence.introducers
                ]
            for entry in entries:
                entry.setdefault("review_status", None)
                entry["manifest_path"] = manifest_path
                key = (package.ecosystem.lower(), manifest_path,
                       entry["package"].casefold(), bool(entry["minimum_fixed_version"]))
                group = grouped.setdefault(key, {"entries": [], "affected_packages": set(), "is_update": False,
                                                 "requires": False, "unverified": False, "notes": []})
                if entry not in group["entries"]:
                    group["entries"].append(entry)
                group["affected_packages"].add(package.package)
                group["is_update"] = group["is_update"] or package.is_update
                recommendation = next((r for r in package.package_upgrade_recommendations
                                       if r.package.casefold() == entry["package"].casefold()), None)
                if recommendation is not None and recommendation.requires_verification:
                    group["requires"] = True
                    if not recommendation.verified_version:
                        group["unverified"] = True
                        failures = [f"{c.version}: {c.verification_message}"
                                    for c in recommendation.qualifying_upgrade_versions
                                    if c.verification_status == "FAILED" and c.verification_message]
                        for note in failures or ([package.notes] if package.notes else []):
                            if note not in group["notes"]:
                                group["notes"].append(note)

        targets = []
        for group in grouped.values():
            entries = group["entries"]
            target = {key: value for key, value in entries[0].items() if key not in {"qualifying_versions", "review_status"}}
            target["is_update"] = group["is_update"]
            target["verification_status"] = (
                None if not group["requires"] else "FAILED" if group["unverified"] else "SUCCESS")
            target["verification_notes"] = "\n".join(group["notes"])
            target["affected_packages"] = sorted(group["affected_packages"])
            current_versions = sorted({entry["current_version"] for entry in entries if entry["current_version"]})
            target["current_version"] = ", ".join(current_versions)
            evidenced = [set(entry["qualifying_versions"]) for entry in entries
                         if entry["qualifying_versions"] is not None]
            common = set.intersection(*evidenced) if evidenced else {
                entry["minimum_fixed_version"] for entry in entries if entry["minimum_fixed_version"]}
            parsed = {}
            for candidate in common:
                try:
                    version = Version(candidate)
                    if all(entry["minimum_fixed_version"] and version >= Version(entry["minimum_fixed_version"])
                           for entry in entries):
                        parsed[version] = candidate
                except InvalidVersion:
                    continue
            ordered = sorted(parsed)
            minimum_versions = {}
            for entry in entries:
                try:
                    minimum_versions[Version(entry["minimum_fixed_version"])] = entry["minimum_fixed_version"]
                except InvalidVersion:
                    continue
            target["minimum_fixed_version"] = minimum_versions[max(minimum_versions)] if minimum_versions else ""
            target["highest_fixed_version"] = parsed[ordered[-1]] if ordered and evidenced else ""
            try:
                current_majors = {Version(current).major for current in current_versions}
            except InvalidVersion:
                current_majors = set()
            # Only successful reviews establish ceilings. The initial compatible
            # value is an inferred candidate, not an upper bound.
            try:
                compatibility_limits = [
                    Version(entry["compatible_version"]) for entry in entries
                    if entry["review_status"] == "upgrade_found"
                ]
                limits_valid = True
            except (InvalidVersion, TypeError):
                compatibility_limits, limits_valid = [], False
            allowed = [
                version for version in ordered
                if evidenced and current_majors == {version.major}
                and not version.is_prerelease and not version.is_devrelease
                and limits_valid and all(version <= limit for limit in compatibility_limits)
                and all(version > Version(current) for current in current_versions)
            ]
            # Retain a single entry's preferred candidate only if evidence supports it.
            # Identical entries follow the same checks after deduplication.
            try:
                preferred = Version(entries[0]["compatible_version"]) if len(entries) == 1 else None
            except (InvalidVersion, TypeError):
                preferred = None
            chosen = preferred if preferred in allowed else next(iter(allowed), None)
            target["compatible_version"] = parsed[chosen] if chosen is not None else ""
            targets.append(target)
        return targets
