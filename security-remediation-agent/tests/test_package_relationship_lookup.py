import sys
import types
from types import SimpleNamespace

sys.modules.setdefault(
    "src.tools.github_sbom_analyzer.sbom_analysis_tool",
    types.SimpleNamespace(sbom_analysis_tool=types.SimpleNamespace(ainvoke=None)),
)

from src.engines.policy_engine.package_relationship_lookup import PackageRelationshipLookup
from src.models.security_package_triage import SecurityPackageTriage


def test_packages_from_result_accepts_data_list() -> None:
    lookup = PackageRelationshipLookup()
    packages = [{"name": "http-proxy-middleware"}]

    assert lookup._packages_from_result({"mode": "packages", "data": packages}) == packages


def test_extract_sources_accepts_alternate_sbom_source_fields() -> None:
    lookup = PackageRelationshipLookup()
    triage = SecurityPackageTriage(
        package="http-proxy-middleware",
        ecosystem="npm",
        current_version_range="<2.0.10",
        remediated_version="2.0.10",
    )
    sbom_matches = [
        {
            "name": "http-proxy-middleware",
            "ecosystem": "npm",
            "dependency_type": "transitive",
            "source_package": {"name": "webpack-dev-server", "version": "4.15.2"},
        }
    ]

    assert lookup._extract_sources(triage, sbom_matches) == [
        "webpack-dev-server@4.15.2"
    ]


def test_extract_sources_accepts_dependency_paths() -> None:
    lookup = PackageRelationshipLookup()
    triage = SecurityPackageTriage(
        package="tar",
        ecosystem="npm",
        current_version_range="<=7.5.15",
        remediated_version="7.5.16",
    )
    sbom_matches = [
        SimpleNamespace(
            name="tar",
            ecosystem="npm",
            dependency_type="transitive",
            dependency_paths=[
                ["node-sass@7.0.3", "cacache@15.3.0", "tar@7.5.15"],
                "node-gyp@8.4.1 -> tar@7.5.15",
            ],
        )
    ]

    assert lookup._extract_sources(triage, sbom_matches) == [
        "node-sass@7.0.3",
        "node-gyp@8.4.1",
    ]


def test_extract_sources_falls_back_to_alert_dependency_hints() -> None:
    lookup = PackageRelationshipLookup()
    triage = SecurityPackageTriage(
        package="form-data",
        ecosystem="npm",
        current_version_range="<4.0.6",
        remediated_version="4.0.6",
        vulnerabilities=[
            SimpleNamespace(depends_on=["axios@0.28.1"]),
        ],
    )

    assert lookup._extract_sources(triage, []) == ["axios@0.28.1"]
