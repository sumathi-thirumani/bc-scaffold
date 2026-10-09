"""Generate an updated Renovate configuration for remediation packages."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from packaging.version import InvalidVersion, Version

from ..engines.remediation_grouping_engine import RemediationGroupingEngine
from ..models.remediation_plan import RemediationPlan, RemeditionPackage
from ..utils.manifest_provider import ManifestProvider

logger = logging.getLogger(__name__)

RENOVATE_CONFIG_PATHS = (
    "renovate.json5",
    ".github/renovate.json5",
    "renovate.json",
    ".github/renovate.json",
)


class RemediationReportAgent:
    def __init__(
        self,
        manifest_provider: ManifestProvider | None = None,
        output_path: str | Path = "renovate.json5",
    ) -> None:
        self.manifest_provider = manifest_provider or ManifestProvider()
        self.output_path = Path(output_path)

    async def report(
        self,
        remediation_plan: RemediationPlan,
        repo: dict[str, str],
        *,
        ref: str | None = None,
    ) -> Path | None:
        rules = self._remediation_package_rules(remediation_plan)
        if not rules:
            logger.info("No remediation packages available for Renovate report")
            return None

        owner = repo.get("owner")
        repository = repo.get("repo") or repo.get("name")
        if not owner or not repository:
            raise ValueError("Repository owner and name are required for Renovate report")

        config = await self._fetch_renovate_config(owner, repository, ref)
        package_rules = config.setdefault("packageRules", [])
        if not isinstance(package_rules, list):
            raise ValueError("Renovate packageRules must be an array")
        package_rules.extend(rules)

        self.output_path.write_text(
            f"{json.dumps(config, indent=2, ensure_ascii=False)}\n",
            encoding="utf-8",
        )
        logger.info(
            "Wrote Renovate remediation report with %d package rules to %s",
            len(rules),
            self.output_path,
        )
        return self.output_path

    async def _fetch_renovate_config(
        self,
        owner: str,
        repo: str,
        ref: str | None,
    ) -> dict[str, Any]:
        for path in RENOVATE_CONFIG_PATHS:
            content = await self.manifest_provider.get(owner, repo, path, ref)
            if content is None:
                continue
            try:
                return RemediationGroupingEngine.parse_json5(content)
            except (ValueError, json.JSONDecodeError) as exc:
                raise ValueError(
                    f"Failed to parse Renovate config at {owner}/{repo}:{path}"
                ) from exc
        logger.info("No Renovate config found for %s/%s; creating a new config", owner, repo)
        return {}

    @classmethod
    def _remediation_package_rules(
        cls,
        remediation_plan: RemediationPlan,
    ) -> list[dict[str, Any]]:
        selected_versions: dict[str, Version] = {}
        display_names: dict[str, str] = {}
        for bundle in remediation_plan.remediation_plan_bundles:
            for package in bundle.packages:
                version = cls._minimum_remediation_version(package)
                if version is None:
                    continue
                key = package.remediation_package.casefold()
                display_names.setdefault(key, package.remediation_package)
                if key not in selected_versions or version < selected_versions[key]:
                    selected_versions[key] = version

        return [
            {
                "matchPackageNames": [display_names[key]],
                "allowedVersions": f">={version} <{version.major + 1}",
            }
            for key, version in sorted(selected_versions.items())
        ]

    @staticmethod
    def _minimum_remediation_version(package: RemeditionPackage) -> Version | None:
        versions: list[Version] = []
        for value in (package.remediation_version, package.upgrade_to_version):
            normalized = (value or "").strip().lstrip("vV")
            if not normalized:
                continue
            try:
                versions.append(Version(normalized))
            except InvalidVersion:
                logger.warning(
                    "Ignoring invalid remediation version %r for %s",
                    value,
                    package.remediation_package,
                )
        return min(versions) if versions else None
