"""Export the complete remediation plan and append verified-version Renovate rules."""
from __future__ import annotations

import json
import logging
import re
from dataclasses import asdict, is_dataclass
from datetime import date, datetime
from enum import Enum
from pathlib import Path

from packaging.version import InvalidVersion, Version

from ..engines.remediation_grouping_engine import RemediationGroupingEngine
from ..models.plan_export import export_plan
from ..models.remediation_plan import RemediationPlan
from ..tools.ecosystem_manifest_tool import ManifestTool

logger = logging.getLogger(__name__)
GENERATED_DESCRIPTION = "Generated remediation verified version"
DATASOURCES = {"npm": "npm", "npm_and_yarn": "npm", "yarn": "npm",
               "pip": "pypi", "pypi": "pypi", "python": "pypi", "poetry": "pypi",
               "uv": "pypi", "nuget": "nuget"}


def to_jsonable(value):
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if is_dataclass(value) and not isinstance(value, type):
        return to_jsonable(asdict(value))
    if hasattr(value, "model_dump"):
        return to_jsonable(value.model_dump())
    if isinstance(value, dict):
        return {str(key): to_jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [to_jsonable(item) for item in value]
    return value


def write_json(path, value, *, compact=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    # Serialize before touching an existing output file.
    options = {"separators": (",", ":")} if compact else {"indent": 2}
    text = json.dumps(to_jsonable(value), ensure_ascii=False, allow_nan=False, **options) + "\n"
    path.write_text(text, encoding="utf-8")


class RemediationArtifactAgent:
    """Export the plan and generate Renovate rules from verified recommendations.

    Core idea: retain the complete diagnostic plan, then add exact-version rules only
    for upgrades that passed resolution. Reuse the collected Renovate configuration
    and replace only this generator's rules, preserving user-authored settings."""
    def __init__(self, manifest_tool: ManifestTool | None = None,
                 output_path: str | Path = "renovate.json5",
                 plan_output_path: str | Path = "remediation-plan.json") -> None:
        self.manifest_tool = manifest_tool
        self.output_path = Path(output_path)
        self.plan_output_path = Path(plan_output_path)
        if self.output_path.resolve() == self.plan_output_path.resolve():
            raise ValueError("Plan and Renovate outputs must use different paths")

    async def report(self, remediation_plan: RemediationPlan, repo: dict[str, str], *,
                     ref: str | None = None) -> Path:
        # Always retain the plan, including unresolved findings and empty runs.
        """Write the full diagnostic plan, then export exact verified-version rules using cached Renovate config."""
        write_json(self.plan_output_path, export_plan(remediation_plan), compact=True)
        owner = repo.get("owner")
        repository = repo.get("repo") or repo.get("name")
        if not owner or not repository:
            raise ValueError("Repository owner and name are required for remediation artifacts")
        if self.manifest_tool is None:
            raise ValueError("A collected ManifestTool is required for remediation artifacts")
        ref = ref if ref is not None else repo.get("ref")
        config = await RemediationGroupingEngine.fetch_renovate_config(
            owner, repository, ref, manifest_tool=self.manifest_tool.offline())
        config = config if config is not None else {}
        rules = config.get("packageRules", [])
        if not isinstance(rules, list):
            raise ValueError("Renovate packageRules must be an array")
        # Replace only rules owned by this generator, preserving user-authored rules.
        config["packageRules"] = [rule for rule in rules if not (
            isinstance(rule, dict) and rule.get("description") == GENERATED_DESCRIPTION)]
        config["packageRules"].extend(self._remediation_package_rules(remediation_plan))
        write_json(self.output_path, config)
        logger.info("Wrote remediation artifacts: %s and %s", self.plan_output_path, self.output_path)
        return self.output_path

    @staticmethod
    def _remediation_package_rules(remediation_plan):
        selected = {}
        for bundle in remediation_plan.remediation_plan_bundles:
            for triage in bundle.packages:
                datasource = DATASOURCES.get(triage.ecosystem.lower())
                path = ManifestTool.declaration_path(triage.ecosystem, triage.manifest_path)
                if not datasource or not path:
                    continue
                for recommendation in triage.package_upgrade_recommendations:
                    version = triage.verified_version(recommendation.package)
                    if not version:
                        continue
                    try:
                        Version(version)
                    except InvalidVersion:
                        logger.warning("Skipping invalid verified version for %s", recommendation.package)
                        continue
                    key = (datasource, path, recommendation.package)
                    # The highest verified version also satisfies the lower advisories.
                    if key not in selected or Version(version) > Version(selected[key]):
                        selected[key] = version
        return [{"description": GENERATED_DESCRIPTION, "matchDatasources": [datasource],
                 "matchFileNames": [path], "matchPackageNames": [name],
                 "allowedVersions": "/^" + re.escape(version) + "$/"}
                for (datasource, path, name), version in sorted(selected.items())]
