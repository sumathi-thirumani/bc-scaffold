import re
from itertools import zip_longest
from typing import Any

from ...models.security_package_triage import SecurityPackageTriage
from ...tools.github_vulnerability_collector.model.vulnerability_alert import VulnerabilityAlert
from ...tools.github_sbom_analyzer.sbom_analysis_tool import sbom_analysis_tool

ECOSYSTEM_ALIASES = {
    "pip": "pypi",
    "actions": "githubactions",
    "gomod": "golang",
    "go": "golang",
}


def normalize_ecosystem(ecosystem: str) -> str:
    key = (ecosystem or "").lower()
    return ECOSYSTEM_ALIASES.get(key, key)


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
            self._populate_package_fields(triage, sbom_matches)
            triage.istransitive = alert_transitive or sbom_transitive

            if not triage.istransitive:
                triage.transitive_source_package = []
                triage.remediation_target_dependency = triage.package
                triage.nearest_declared_parent = triage.package
                triage.graph_confidence = "high" if sbom_matches else "low"
                triage.graph_status = "dependency graph available" if sbom_matches else "sbom package not found"
                continue

            triage.transitive_source_package = self._extract_sources(
                triage,
                sbom_matches,
                sbom_transitive,
            )
            triage.nearest_declared_parent = (
                self._strip_version_suffix(triage.transitive_source_package[0])
                if triage.transitive_source_package
                else ""
            )
            triage.remediation_target_dependency = triage.nearest_declared_parent
            triage.dependency_path = (
                [triage.nearest_declared_parent, triage.package]
                if triage.nearest_declared_parent
                else []
            )
            triage.graph_confidence = "high" if triage.transitive_source_package else "unavailable"
            triage.graph_status = (
                "dependency graph available"
                if triage.transitive_source_package
                else "dependency graph unavailable"
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
            if normalize_ecosystem(str(p.get("ecosystem", ""))) == normalize_ecosystem(triage.ecosystem)
        ]

    def _extract_sources(
        self,
        triage: SecurityPackageTriage,
        sbom_matches: list[dict[str, Any]],
        sbom_transitive: bool,
    ) -> list[str]:
        raw: list[str] = []

        if sbom_transitive:
            transitive_matches = [
                p
                for p in sbom_matches
                if str(p.get("dependency_type", "")).lower() == "transitive"
                and self._sbom_version_in_range(
                    str(p.get("version", "")),
                    triage.current_version_range,
                )
            ]
            if not transitive_matches:
                transitive_matches = [
                    p
                    for p in sbom_matches
                    if str(p.get("dependency_type", "")).lower() == "transitive"
                ]
            for package in transitive_matches:
                raw.extend(package.get("source_packages") or [])
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

    def _populate_package_fields(
        self,
        triage: SecurityPackageTriage,
        sbom_matches: list[dict[str, Any]],
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

    def _strip_version_suffix(self, package_ref: str) -> str:
        parts = package_ref.split("@")
        if package_ref.startswith("@"):
            return "@" + parts[1] if len(parts) >= 3 else package_ref
        return parts[0]

    def _sbom_version_in_range(self, version: str, vulnerable_range: str) -> bool:
        if not version or not vulnerable_range:
            return True

        for clause in [c.strip() for c in vulnerable_range.split(",") if c.strip()]:
            match = re.match(r"([><=!]+)\s*([\d][^\s]*)", clause)
            if not match:
                continue
            op, bound = match.group(1), match.group(2)
            cmp = self.compare_version_keys(
                self.version_sort_key(version),
                self.version_sort_key(bound),
            )
            if op == ">=" and cmp < 0:
                return False
            if op == ">" and cmp <= 0:
                return False
            if op == "<" and cmp >= 0:
                return False
            if op == "<=" and cmp > 0:
                return False
            if op == "=" and cmp != 0:
                return False
            if op == "!=" and cmp == 0:
                return False
        return True

    def version_sort_key(self, version: str) -> tuple[Any, ...]:
        parts = re.split(r"[.\-+_]", re.sub(r"^[^0-9]*", "", version))
        parsed_parts: list[tuple[int, Any]] = []
        for part in parts:
            if part.isdigit():
                parsed_parts.append((1, int(part)))
            elif part:
                parsed_parts.append((0, part))
        return tuple(parsed_parts)

    def compare_version_keys(
        self,
        left: tuple[Any, ...],
        right: tuple[Any, ...],
    ) -> int:
        for left_part, right_part in zip_longest(left, right, fillvalue=(1, 0)):
            if left_part == right_part:
                continue
            return 1 if left_part > right_part else -1
        return 0
