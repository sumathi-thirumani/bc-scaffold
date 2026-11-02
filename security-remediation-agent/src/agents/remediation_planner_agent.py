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
        return RemediationPlan(
            remediation_plan_bundles=await self._build_remediation_package_bundles(triage_items, repo, ref),
            summary=context,
        )
