import pytest
import sys
import types

sys.modules.setdefault(
    "src.tools.github_sbom_analyzer.sbom_analysis_tool",
    types.SimpleNamespace(sbom_analysis_tool=types.SimpleNamespace(ainvoke=None)),
)

from src.engines.policy_engine.dependency_graph import DependencyGraph
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


def package_lock_v3():
    return {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"axios": "0.28.1", "lodash": "4.17.20"}},
            "node_modules/axios": {
                "version": "0.28.1",
                "dependencies": {"form-data": "4.0.4"},
            },
            "node_modules/form-data": {"version": "4.0.4"},
            "node_modules/lodash": {"version": "4.17.20"},
        },
    }


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
        StubTool({"package_lock": package_lock_v3()}),
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
        StubTool({"package_lock": package_lock_v3()}),
    )

    await PackageRelationshipLookup().populate_relationship_details("octo", "repo", [triage])

    assert triage.istransitive is True
    assert triage.dependency_path == ["axios", "form-data"]
    assert triage.nearest_declared_parent == "axios"
    assert triage.remediation_target_dependency == "axios"
    assert triage.transitive_source_package == ["axios"]


def test_multiple_dependency_paths():
    graph = DependencyGraph.from_npm_lockfile(
        {
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"a": "1.0.0", "b": "1.0.0"}},
                "node_modules/a": {"version": "1.0.0", "dependencies": {"x": "1.0.0"}},
                "node_modules/b": {"version": "1.0.0", "dependencies": {"x": "1.0.0"}},
                "node_modules/x": {"version": "1.0.0"},
            },
        }
    )

    resolution = graph.resolve("x", "npm")

    assert sorted(resolution.dependency_paths) == [["a", "x"], ["b", "x"]]
    assert resolution.nearest_declared_parent == "a"


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


def test_package_lock_v2_v3_traversal():
    graph = DependencyGraph.from_npm_lockfile(package_lock_v3())

    assert graph.resolve("lodash", "npm").relationship == "direct"
    form_data = graph.resolve("form-data", "npm")
    assert form_data.relationship == "transitive"
    assert form_data.dependency_path == ["axios", "form-data"]
