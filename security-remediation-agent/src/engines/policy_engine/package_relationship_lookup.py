import re
from typing import Any

from .dependency_graph import DependencyGraph, DependencyGraphResolution
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
        graph = self._graph_from_result(result)

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
            graph_resolution = graph.resolve(triage.package, triage.ecosystem) if graph else None

            self._populate_graph_fields(triage, sbom_matches, graph_resolution)

            if graph_resolution and graph_resolution.relationship in {"direct", "transitive"}:
                triage.istransitive = graph_resolution.relationship == "transitive"
            else:
                triage.istransitive = alert_transitive or sbom_transitive

            if not triage.istransitive:
                triage.transitive_source_package = []
                triage.remediation_target_dependency = triage.package
                continue

            if graph_resolution and graph_resolution.nearest_declared_parent:
                triage.transitive_source_package = [self._format_parent(graph_resolution.nearest_declared_parent)]
                triage.remediation_target_dependency = graph_resolution.nearest_declared_parent
            else:
                triage.transitive_source_package = self._extract_sources(
                    triage,
                    sbom_matches,
                    sbom_transitive,
                )
                triage.remediation_target_dependency = self._strip_version_suffix(
                    triage.transitive_source_package[0]
                ) if triage.transitive_source_package else ""
                if not triage.transitive_source_package:
                    triage.graph_confidence = "unavailable"
                    triage.graph_status = "dependency graph unavailable"

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

    def _graph_from_result(self, result: Any) -> DependencyGraph | None:
        if not isinstance(result, dict):
            return None
        graph = result.get("dependency_graph")
        if isinstance(graph, DependencyGraph):
            return graph
        lockfile = result.get("package_lock") or result.get("package-lock.json")
        if isinstance(lockfile, dict):
            return DependencyGraph.from_npm_lockfile(
                lockfile,
                manifest_path=result.get("manifest_path", "package.json"),
                lockfile_path=result.get("lockfile_path", "package-lock.json"),
            )
        data = result.get("data")
        if isinstance(data, dict):
            return self._graph_from_result(data)
        return None

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
        sbom_transitive: bool,
    ) -> list[str]:
        raw: list[str] = []

        if sbom_transitive:
            for p in sbom_matches:
                if str(p.get("dependency_type", "")).lower() == "transitive":
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

    def _populate_graph_fields(
        self,
        triage: SecurityPackageTriage,
        sbom_matches: list[dict[str, Any]],
        graph_resolution: DependencyGraphResolution | None,
    ) -> None:
        triage.fixed_version = triage.remediated_version
        if sbom_matches:
            match = sbom_matches[0]
            triage.installed_version = str(match.get("version") or triage.installed_version)
            triage.manifest_path = str(match.get("manifest_path") or triage.manifest_path)
            triage.lockfile_path = str(match.get("lockfile_path") or triage.lockfile_path)
            if not triage.graph_confidence or triage.graph_confidence == "unavailable":
                triage.graph_confidence = "low"
                triage.graph_status = "sbom relationship only"

        if not graph_resolution:
            return

        triage.installed_version = graph_resolution.installed_version or triage.installed_version
        triage.manifest_path = graph_resolution.manifest_path or triage.manifest_path
        triage.lockfile_path = graph_resolution.lockfile_path or triage.lockfile_path
        triage.dependency_path = graph_resolution.dependency_path
        triage.nearest_declared_parent = graph_resolution.nearest_declared_parent
        triage.remediation_target_dependency = graph_resolution.remediation_target_dependency
        triage.graph_confidence = graph_resolution.graph_confidence
        triage.graph_status = (
            "dependency graph available"
            if graph_resolution.graph_confidence in {"high", "low"}
            else "dependency graph unavailable"
        )

    def _format_parent(self, parent: str) -> str:
        return parent

    def _strip_version_suffix(self, package_ref: str) -> str:
        parts = package_ref.split("@")
        if package_ref.startswith("@"):
            return "@" + parts[1] if len(parts) >= 3 else package_ref
        return parts[0]
