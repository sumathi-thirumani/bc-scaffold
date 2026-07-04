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
            name = self._pkg_get(pkg, "name")
            if name:
                packages_by_name.setdefault(str(name).lower(), []).append(pkg)

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
        if isinstance(data, list):
            return data
        if isinstance(data, dict) and isinstance(data.get("packages"), list):
            return data["packages"]

        return []

    def _is_transitive_from_sbom(self, sbom_matches: list[dict[str, Any]]) -> bool:
        return any(
            str(self._pkg_get(p, "dependency_type", "")).lower() == "transitive"
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
            if str(self._pkg_get(p, "ecosystem", "")).lower()
            == triage.ecosystem.lower()
        ]

    def _extract_sources(
        self,
        triage: SecurityPackageTriage,
        sbom_matches: list[dict[str, Any]],
    ) -> list[str]:
        raw: list[str] = []

        for p in sbom_matches:
            raw.extend(self._source_packages_from_match(p))

        if not raw:
            for alert in triage.vulnerabilities:
                raw.extend(self._source_packages_from_alert(alert))

        return [
            source
            for source in dict.fromkeys(raw)
            if not self._is_repo_root_source(source)
        ]

    def _is_repo_root_source(self, source: str) -> bool:
        return bool(self._REPO_ROOT_SOURCE_RE.match(source))

    def _pkg_get(self, package: Any, key: str, default: Any = None) -> Any:
        if isinstance(package, dict):
            return package.get(key, default)
        return getattr(package, key, default)

    def _source_packages_from_match(self, package: Any) -> list[str]:
        raw_sources: list[Any] = []
        for key in (
            "source_packages",
            "source_package",
            "sourceDependencies",
            "source_dependencies",
            "depends_on",
        ):
            value = self._pkg_get(package, key)
            if value:
                raw_sources.extend(self._coerce_sources(value))

        paths = self._pkg_get(package, "dependency_paths")
        if paths:
            raw_sources.extend(self._sources_from_dependency_paths(paths))

        return self._clean_sources(raw_sources)

    def _source_packages_from_alert(self, alert: VulnerabilityAlert) -> list[str]:
        raw_sources: list[Any] = []
        for key in (
            "depends_on",
            "source_packages",
            "source_package",
            "dependency_path",
            "dependency_paths",
        ):
            value = getattr(alert, key, None)
            if value:
                if key in ("dependency_path", "dependency_paths"):
                    raw_sources.extend(self._sources_from_dependency_paths(value))
                else:
                    raw_sources.extend(self._coerce_sources(value))

        return self._clean_sources(raw_sources)

    def _coerce_sources(self, value: Any) -> list[Any]:
        if isinstance(value, str):
            return [value]
        if isinstance(value, dict):
            return [value]
        if isinstance(value, list | tuple | set):
            return list(value)
        return []

    def _sources_from_dependency_paths(self, paths: Any) -> list[Any]:
        sources: list[Any] = []
        for path in self._coerce_sources(paths):
            if isinstance(path, str):
                parts = [p.strip() for p in re.split(r"\s*(?:->|→)\s*", path) if p.strip()]
                if parts:
                    sources.append(parts[0])
                continue
            if isinstance(path, list | tuple) and path:
                sources.append(path[0])
        return sources

    def _clean_sources(self, sources: list[Any]) -> list[str]:
        cleaned: list[str] = []
        for source in sources:
            if isinstance(source, dict):
                name = source.get("name") or source.get("package")
                version = source.get("version")
                if not name:
                    continue
                source = f"{name}@{version}" if version else name

            text = str(source).strip()
            if text:
                cleaned.append(text)
        return cleaned
