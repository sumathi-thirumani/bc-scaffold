import re
from typing import Any

from ...models.security_package_triage import SecurityPackageTriage
from ...tools.github_vulnerability_collector.model.vulnerability_alert import VulnerabilityAlert
from ...tools.github_sbom_analyzer.sbom_analysis_tool import sbom_analysis_tool


class PackageRelationshipLookup:
    _REPO_ROOT_SOURCE_RE = re.compile(r"^com\.github\.[^/]+/[^@]+@", re.IGNORECASE)

    async def populate_relationship_details(
        self,
        owner: str,
        repo: str,
        triage_items: list[SecurityPackageTriage],
    ) -> None:
        result = await sbom_analysis_tool.ainvoke({"owner": owner, "repo": repo})
        packages = self._packages_from_result(result)

        packages_by_name: dict[str, list[dict[str, Any]]] = {}
        for pkg in packages:
            name = pkg.get("name")
            if name:
                packages_by_name.setdefault(name.lower(), []).append(pkg)

        for triage in triage_items:
            alert_transitive = self._is_transitive_from_alerts(triage.vulnerabilities)
            sbom_matches = packages_by_name.get(triage.package.lower(), [])
            sbom_matches = self._filter_by_ecosystem(triage, sbom_matches)
            sbom_transitive = self._is_transitive_from_sbom(sbom_matches)

            triage.istransitive = alert_transitive or sbom_transitive

            if not triage.istransitive:
                triage.transitive_source_package = []
                continue

            triage.transitive_source_package = self._extract_sources(
                triage,
                sbom_matches,
            )

    def _is_transitive_from_alerts(self, alerts: list[VulnerabilityAlert]) -> bool:
        return any(a.relationship.lower() == "indirect" for a in alerts)

    def _packages_from_result(self, result: Any) -> list[dict[str, Any]]:
        if not isinstance(result, dict):
            return []

        packages = result.get("packages")
        if isinstance(packages, list):
            return packages

        data = result.get("data")
        if isinstance(data, dict) and isinstance(data.get("packages"), list):
            return data["packages"]

        return []

    def _is_transitive_from_sbom(self, sbom_matches: list[dict[str, Any]]) -> bool:
        return any(
            str(p.get("dependency_type", "")).lower() == "transitive"
            for p in sbom_matches
        )

    def _filter_by_ecosystem(
        self,
        triage: SecurityPackageTriage,
        packages: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        if not triage.ecosystem:
            return packages

        return [
            p
            for p in packages
            if p.get("ecosystem", "").lower() == triage.ecosystem.lower()
        ]

    def _extract_sources(
        self,
        triage: SecurityPackageTriage,
        sbom_matches: list[dict[str, Any]],
    ) -> list[str]:
        raw: list[str] = []

        if sbom_matches:
            for p in sbom_matches:
                raw.extend(p.get("source_packages") or [])
        else:
            for alert in triage.vulnerabilities:
                raw.extend(getattr(alert, "depends_on", []) or [])

        return [
            source
            for source in dict.fromkeys(raw)
            if not self._is_repo_root_source(source)
        ]

    def _is_repo_root_source(self, source: str) -> bool:
        return bool(self._REPO_ROOT_SOURCE_RE.match(source))
