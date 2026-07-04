import pytest
import sys
import types

sys.modules.setdefault(
    "src.tools.github_sbom_analyzer.sbom_analysis_tool",
    types.SimpleNamespace(sbom_analysis_tool=types.SimpleNamespace(ainvoke=None)),
)

from src.engines.policy_engine.package_relationship_lookup import PackageRelationshipLookup
from src.models.security_package_triage import SecurityPackageTriage
from src.tools.github_vulnerability_collector.model.vulnerability_alert import VulnerabilityAlert


class StubTool:
    def __init__(self, result):
        self.result = result

    async def ainvoke(self, tool_input):
        return self.result


def make_alert(package: str, relationship: str = "") -> VulnerabilityAlert:
    return VulnerabilityAlert(
        package=package,
        ecosystem="npm",
        severity="high",
        ghsa_id=f"GHSA-{package}",
        first_patched="9.9.9",
        vulnerable_range="<9.9.9",
        relationship=relationship,
    )


def sbom_packages():
    return [
        {
            "name": "axios",
            "version": "0.28.1",
            "ecosystem": "npm",
            "dependency_type": "direct",
            "source_packages": [],
            "manifest_path": "package.json",
            "lockfile_path": "package-lock.json",
        },
        {
            "name": "form-data",
            "version": "4.0.4",
            "ecosystem": "npm",
            "dependency_type": "transitive",
            "source_packages": ["axios@0.28.1"],
            "manifest_path": "package.json",
            "lockfile_path": "package-lock.json",
        },
    ]


@pytest.mark.asyncio
async def test_direct_dependency_detection(monkeypatch):
    triage = SecurityPackageTriage(
        package="axios",
        ecosystem="npm",
        current_version_range="<1.0.0",
        remediated_version="1.0.0",
        vulnerabilities=[make_alert("axios", "direct")],
    )
    monkeypatch.setattr(
        "src.engines.policy_engine.package_relationship_lookup.sbom_analysis_tool",
        StubTool({"packages": sbom_packages()}),
    )

    await PackageRelationshipLookup().populate_relationship_details("octo", "repo", [triage])

    assert triage.istransitive is False
    assert triage.installed_version == "0.28.1"
    assert triage.remediation_target_dependency == "axios"
    assert triage.graph_confidence == "high"


@pytest.mark.asyncio
async def test_transitive_dependency_detection_and_nearest_parent(monkeypatch):
    triage = SecurityPackageTriage(
        package="form-data",
        ecosystem="npm",
        current_version_range="<4.0.6",
        remediated_version="4.0.6",
        vulnerabilities=[make_alert("form-data", "indirect")],
    )
    monkeypatch.setattr(
        "src.engines.policy_engine.package_relationship_lookup.sbom_analysis_tool",
        StubTool({"packages": sbom_packages()}),
    )

    await PackageRelationshipLookup().populate_relationship_details("octo", "repo", [triage])

    assert triage.istransitive is True
    assert triage.dependency_path == ["axios", "form-data"]
    assert triage.nearest_declared_parent == "axios"
    assert triage.remediation_target_dependency == "axios"
    assert triage.transitive_source_package == ["axios@0.28.1"]


@pytest.mark.asyncio
async def test_multiple_dependency_paths(monkeypatch):
    triage = SecurityPackageTriage(
        package="x",
        ecosystem="npm",
        current_version_range="<1.0.1",
        remediated_version="1.0.1",
        vulnerabilities=[make_alert("x", "indirect")],
    )
    monkeypatch.setattr(
        "src.engines.policy_engine.package_relationship_lookup.sbom_analysis_tool",
        StubTool({
            "packages": [
                {
                    "name": "x",
                    "version": "1.0.0",
                    "ecosystem": "npm",
                    "dependency_type": "transitive",
                    "source_packages": ["a@1.0.0", "b@1.0.0"],
                }
            ]
        }),
    )

    await PackageRelationshipLookup().populate_relationship_details("octo", "repo", [triage])

    assert triage.transitive_source_package == ["a@1.0.0", "b@1.0.0"]
    assert triage.nearest_declared_parent == "a"


@pytest.mark.asyncio
async def test_missing_graph_fallback_marks_unavailable(monkeypatch):
    triage = SecurityPackageTriage(
        package="form-data",
        ecosystem="npm",
        current_version_range="<4.0.6",
        remediated_version="4.0.6",
        vulnerabilities=[make_alert("form-data", "indirect")],
    )
    monkeypatch.setattr(
        "src.engines.policy_engine.package_relationship_lookup.sbom_analysis_tool",
        StubTool({"packages": []}),
    )

    await PackageRelationshipLookup().populate_relationship_details("octo", "repo", [triage])

    assert triage.istransitive is True
    assert triage.transitive_source_package == []
    assert triage.graph_confidence == "unavailable"
    assert triage.graph_status == "dependency graph unavailable"


@pytest.mark.asyncio
async def test_version_range_filters_unrelated_sbom_paths(monkeypatch):
    triage = SecurityPackageTriage(
        package="form-data",
        ecosystem="npm",
        current_version_range=">=4.0.0, <4.0.6",
        remediated_version="4.0.6",
        vulnerabilities=[make_alert("form-data", "indirect")],
    )
    monkeypatch.setattr(
        "src.engines.policy_engine.package_relationship_lookup.sbom_analysis_tool",
        StubTool({
            "packages": [
                {
                    "name": "form-data",
                    "version": "2.3.3",
                    "ecosystem": "npm",
                    "dependency_type": "transitive",
                    "source_packages": ["old-parent@1.0.0"],
                },
                {
                    "name": "form-data",
                    "version": "4.0.4",
                    "ecosystem": "npm",
                    "dependency_type": "transitive",
                    "source_packages": ["axios@0.28.1"],
                },
            ]
        }),
    )

    await PackageRelationshipLookup().populate_relationship_details("octo", "repo", [triage])

    assert triage.transitive_source_package == ["axios@0.28.1"]
