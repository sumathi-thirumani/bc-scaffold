import json
import sys
import subprocess
import pytest
from pathlib import Path
from unittest.mock import AsyncMock

from src.engines.package_relationship_resolver import PackageRelationshipResolver
from src.engines.resolvers.relationship_version_resolvers.pip_relationship_version_resolver import (
    PipRelationshipVersionResolver,
)
from src.tools.ecosystem_manifest_tool import ManifestTool
from src.models.security_package_triage import SecurityPackageTriage


def _report():
    return {
        "install": [
            {
                "requested": True,
                "metadata": {
                    "name": "app",
                    "version": "1.0.0",
                    "requires_dist": [
                        "middle>=1,<2",
                        "featuredep>=1; extra == 'api'",
                    ],
                },
            },
            {
                "requested": False,
                "metadata": {
                    "name": "middle",
                    "version": "1.5.0",
                    "requires_dist": ["vulnerable>=3; python_version >= '3.10'"],
                },
            },
            {
                "requested": False,
                "metadata": {"name": "vulnerable", "version": "3.2.0"},
            },
            {
                "requested": False,
                "metadata": {"name": "featuredep", "version": "1.4.0"},
            },
        ],
    }


def test_pip_dry_run_report_resolves_direct_and_transitive_paths(monkeypatch):
    # Windows environment discovery can itself run a subprocess; keep the CLI mock focused on pip.
    from packaging.markers import default_environment
    default_environment()
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        report_path = Path(command[command.index("--report") + 1])
        report_path.write_text(json.dumps(_report()), encoding="utf-8")
        return type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    monkeypatch.setattr(
        "src.engines.resolvers.relationship_version_resolvers.pip_relationship_version_resolver.subprocess.run",
        run,
    )
    resolver = PipRelationshipVersionResolver(
        "-r base.in\n",
        requirements_path="requirements.in",
        support_files={"base.in": "app[api]==1.0.0\n"},
    )

    resolver.prefetch(["vulnerable", "featuredep"])
    vulnerable = resolver.resolve("VULNERABLE")
    featuredep = resolver.resolve("featuredep")

    assert len(calls) == 1
    assert calls[0][:7] == [
        sys.executable,
        "-m",
        "pip",
        "install",
        "--dry-run",
        "--ignore-installed",
        "--report",
    ]
    assert calls[0][-2:] == ["-r", "requirements.in"]
    [vulnerable_occurrence] = vulnerable["occurrences"]
    assert vulnerable_occurrence["is_root"] is False
    assert [node["package"] for node in vulnerable_occurrence["paths"][0]] == [
        "app", "middle", "vulnerable",
    ]
    [featuredep_occurrence] = featuredep["occurrences"]
    assert [node["package"] for node in featuredep_occurrence["paths"][0]] == [
        "app", "featuredep",
    ]


def test_pip_failure_logs_captured_diagnostics(monkeypatch, caplog):
    monkeypatch.setattr(
        "src.engines.resolvers.relationship_version_resolvers.pip_relationship_version_resolver.subprocess.run",
        lambda command, **kwargs: subprocess.CompletedProcess(
            command, 1, stdout="", stderr="No module named pip",
        ),
    )
    resolver = PipRelationshipVersionResolver("fastapi\n", requirements_path="api/requirements.in")
    with pytest.raises(subprocess.CalledProcessError):
        resolver.resolve("starlette")
    assert "api/requirements.in" in caplog.text
    assert "No module named pip" in caplog.text


async def test_requirements_in_is_preferred_to_compiled_txt():
    manifest_tool = type("Tool", (), {})()
    manifest_tool.get = AsyncMock(side_effect=lambda owner, repo, path, ref: {
        "services/api/requirements.in": "requests>=2\n",
        "services/api/requirements.txt": "requests==2.0\n",
    }.get(path))
    resolver = PackageRelationshipResolver(manifest_tool=manifest_tool)

    for manifest in ("services/api/requirements.txt", "services/api/requirements.in"):
        path = await resolver._pip_requirements_path("owner", "repo", manifest, "commit")
        assert path == "services/api/requirements.in"


async def test_requirements_in_is_used_when_no_txt_exists():
    manifest_tool = type("Tool", (), {})()
    manifest_tool.get = AsyncMock(side_effect=lambda owner, repo, path, ref: {
        "services/api/requirements.in": "requests>=2\n",
    }.get(path))
    resolver = PackageRelationshipResolver(manifest_tool=manifest_tool)

    path = await resolver._pip_requirements_path(
        "owner", "repo", "services/api/requirements.in", "commit"
    )

    assert path == "services/api/requirements.in"


@pytest.mark.asyncio
@pytest.mark.parametrize("manifest", ["api/requirements.in", "api/requirements.txt"])
async def test_txt_is_used_when_source_manifest_is_absent(manifest):
    tool = type("Tool", (), {})()
    tool.get = AsyncMock(side_effect=lambda owner, repo, path, ref:
        "starlette==0.50.0\n" if path == "api/requirements.txt" else None)
    resolver = PackageRelationshipResolver(manifest_tool=tool)
    assert await resolver._pip_requirements_path("owner", "repo", manifest, "main") == "api/requirements.txt"


async def test_hidden_requirements_txt_is_used_as_declared():
    manifest_tool = type("Tool", (), {})()
    manifest_tool.get = AsyncMock(side_effect=lambda owner, repo, path, ref:
        "requests>=2\n" if path == "services/api/.requirements.txt" else None)
    resolver = PackageRelationshipResolver(manifest_tool=manifest_tool)

    path = await resolver._pip_requirements_path(
        "owner", "repo", "services/api/.requirements.txt", "commit"
    )

    assert path == "services/api/.requirements.txt"
    assert ManifestTool.is_dependency_manifest("services/api/.requirements.txt")


@pytest.mark.asyncio
@pytest.mark.parametrize("declared_starlette", [False, True])
async def test_source_dry_run_keeps_starlette_parent_paths(monkeypatch, declared_starlette):
    compiled = "fastapi==0.125.0\nfastapi-sqlalchemy==0.2.1\nstarlette==0.50.0\n"
    source = "fastapi\nfastapi-sqlalchemy\n" + ("starlette\n" if declared_starlette else "")
    files = {"api/requirements.txt": compiled, "api/requirements.in": source}
    reports = []

    def report(resolver):
        reports.append((resolver.requirements_path, resolver.requirements_text))
        return {"install": [
            {"requested": True, "metadata": {
                "name": "fastapi", "version": "0.125.0", "requires_dist": ["starlette>=0.40,<0.51"],
            }},
            {"requested": True, "metadata": {
                "name": "fastapi-sqlalchemy", "version": "0.2.1", "requires_dist": ["starlette>=0.10"],
            }},
            {"requested": declared_starlette, "metadata": {"name": "starlette", "version": "0.50.0"}},
        ]}

    monkeypatch.setattr(PipRelationshipVersionResolver, "_run_report", report)
    tool = ManifestTool(token="token")
    tool.repository_tree = AsyncMock(return_value=[{"path": path} for path in files])
    tool.get = AsyncMock(side_effect=lambda owner, repo, path, ref: files.get(path))
    item = SecurityPackageTriage(
        package="starlette", ecosystem="pip", manifest_path="api/requirements.txt",
        istransitive=False, vulnerablility_version_range="<0.51", vulnerablility_fixed_version="0.51",
    )
    await PackageRelationshipResolver(manifest_tool=tool).populate("owner", "repo", [item], ref="main")
    assert reports == [("api/requirements.in", source)]
    assert item.istransitive is not declared_starlette
    [occurrence] = item.transitive_dependency_occurrences
    assert occurrence.version == "0.50.0"
    assert {parent.package for parent in occurrence.introducers} == {"fastapi", "fastapi-sqlalchemy"}
    assert {tuple(node.package for node in path) for path in occurrence.paths if len(path) > 1} == {
        ("fastapi", "starlette"), ("fastapi-sqlalchemy", "starlette"),
    }


def test_plain_requirements_preserve_pip_requested_flag():
    resolver = PipRelationshipVersionResolver("starlette==0.50.0\n")
    resolver._load_report({"install": [{
        "requested": True, "metadata": {"name": "starlette", "version": "0.50.0"},
    }]})
    resolver._build_parent_graph()
    assert resolver._resolve("starlette", "starlette")["occurrences"][0]["is_root"] is True


@pytest.mark.parametrize("include", ["-r base.in", "-rbase.in", "--requirement=base.in"])
def test_source_extras_follow_includes_and_comments(include):
    resolver = PipRelationshipVersionResolver(
        include + "\n", requirements_path="api/requirements.in",
        support_files={
            "api/base.in": "app[api]==1.0 # requested extra\n",
        },
    )
    assert resolver._direct_extras() == {"app": {"api"}}


def test_direct_current_version_survives_vulnerability_filtering():
    item = SecurityPackageTriage(
        package="starlette", ecosystem="pip", manifest_path="api/requirements.txt",
        vulnerablility_version_range="<1.3.1", vulnerablility_fixed_version="1.3.1",
    )
    PackageRelationshipResolver._add_transitive_occurrences(item, {"occurrences": [{
        "package": "starlette", "version": "1.3.1", "is_root": True, "introducers": [],
    }]}, "api/requirements.txt", vulnerable_range="<1.3.1", fixed_version="1.3.1")
    assert item.current_version == "1.3.1"
    assert item.transitive_dependency_occurrences == []
