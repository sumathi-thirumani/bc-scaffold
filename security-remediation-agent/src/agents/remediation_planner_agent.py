"""Group triaged findings into remediation bundles without losing their evidence."""
import logging

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
    def __init__(self, manifest_tool: ManifestTool | None = None) -> None:
        self.manifest_tool = manifest_tool

    @staticmethod
    def _version_upgrade_type(current: str, target: str) -> str:
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
        if not package.istransitive:
            return cls._version_upgrade_type(package.current_version, package.vulnerablility_fixed_version)
        # A finding may require several parent upgrades. Use the largest required bump;
        # keep every recommendation on the original triage object.
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
        grouped: dict[tuple[str, str], list[SecurityPackageTriage]] = {}
        for package in triage_items:
            key = (package.ecosystem.lower() or "unknown", cls._upgrade_type(package))
            grouped.setdefault(key, []).append(package)
        bundles = []
        for key in sorted(grouped, key=lambda key: (key[0], UPGRADE_ORDER[key[1]])):
            ecosystem, kind = key
            bundles.append(RemeditionPackageBundle(
                ecosystem=ecosystem, groupName=f"{ecosystem}/{kind}",
                severity=cls._bundle_severity(grouped[key]),
                packages=sorted(grouped[key], key=lambda item: (item.package.casefold(), item.manifest_path or "")),
            ))
        return bundles

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
        for bundle in remediation_plan.remediation_plan_bundles:
            bundle.upgrade_targets = cls._build_upgrade_targets(bundle.packages)

    @staticmethod
    def _build_upgrade_targets(packages: list[SecurityPackageTriage]) -> list[dict]:
        grouped = {}
        for package in packages:
            entries = [
                {"package": recommendation.package, "current_version": recommendation.from_version,
                 "minimum_fixed_version": recommendation.minimum_patched_version,
                 "compatible_version": recommendation.compatible_version,
                 "highest_fixed_version": recommendation.highest_stable_version,
                 "qualifying_versions": recommendation.qualifying_upgrade_versions}
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
                group = grouped.setdefault(entry["package"].casefold(), {"entries": [], "affected_packages": set()})
                if entry not in group["entries"]:
                    group["entries"].append(entry)
                group["affected_packages"].add(package.package)

        targets = []
        for group in grouped.values():
            entries = group["entries"]
            target = {key: value for key, value in entries[0].items() if key != "qualifying_versions"}
            target["affected_packages"] = sorted(group["affected_packages"])
            current_versions = sorted({entry["current_version"] for entry in entries if entry["current_version"]})
            target["current_version"] = ", ".join(current_versions)
            if len(entries) > 1:
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
                target["minimum_fixed_version"] = parsed[ordered[0]] if ordered else ""
                target["highest_fixed_version"] = parsed[ordered[-1]] if ordered and evidenced else ""
                try:
                    current_majors = {Version(current).major for current in current_versions}
                except InvalidVersion:
                    current_majors = set()
                target["compatible_version"] = next(
                    (parsed[version] for version in ordered if evidenced and current_majors == {version.major}), "")
            targets.append(target)
        return targets
