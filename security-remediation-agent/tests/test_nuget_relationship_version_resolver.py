import json
import subprocess
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from src.engines.package_relationship_resolver import PackageRelationshipResolver
from src.engines.resolver_factory import RelationshipResolverFactory
from src.engines.resolvers.relationship_version_resolvers import (
    nuget_relationship_version_resolver,
)
from src.models.security_package_triage import SecurityPackageTriage
from src.tools.ecosystem_manifest_tool import ManifestTool


def _assets(targets, frameworks):
    return {"targets": targets, "project": {"frameworks": frameworks}}


def _install_assets(monkeypatch, project_assets):
    def run(command, **kwargs):
        if command[1] == "--version":
            return subprocess.CompletedProcess(command, 0, stdout="10.0.100", stderr="")
        if command[1] != "restore":
            raise AssertionError(f"Unexpected command: {command}")
        project_path = command[2]
        report = project_assets[project_path]
        if isinstance(report, Exception):
            return subprocess.CompletedProcess(command, 1, stdout="", stderr=str(report))
        assets_path = (
            Path(kwargs["cwd"])
            / Path(project_path).parent
            / "obj"
            / "project.assets.json"
        )
        assets_path.parent.mkdir(parents=True, exist_ok=True)
        assets_path.write_text(json.dumps(report), encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(
        "src.engines.resolvers.relationship_version_resolvers.nuget_relationship_version_resolver.subprocess.run",
        run,
    )


def test_resolves_all_direct_introducers_and_dependency_paths(monkeypatch):
    project = "src/App.csproj"
    report = _assets(
        {".NETCoreApp,Version=v8.0": {
            "WebApp/2.0.0": {"type": "package", "dependencies": {"Middle.Library": "1.0.0"}},
            "Middle.Library/1.0.0": {
                "type": "package",
                "dependencies": {"Vulnerable.Library": "1.5.0"},
            },
            "WorkerApp/3.0.0": {"type": "package", "dependencies": {"Vulnerable.Library": "1.5.0"}},
            "Vulnerable.Library/1.5.0": {"type": "package"},
        }},
        {"net8.0": {"targetAlias": "net8.0", "dependencies": {
            "WebApp": {"target": "Package", "version": "2.0.0"},
            "WorkerApp": {"target": "Package", "version": "3.0.0"},
        }}},
    )
    _install_assets(monkeypatch, {project: report})
    resolver = nuget_relationship_version_resolver.NuGetRelationshipVersionResolver(
        {project: "<Project />"}, dotnet_executable="dotnet"
    )

    result = resolver.resolve("vulnerable.library", project)

    assert result["version"] == "1.5.0"
    [occurrence] = result["occurrences"]
    assert {item["package"] for item in occurrence["introducers"]} == {"WebApp", "WorkerApp"}
    assert {
        tuple(node["package"] for node in path) for path in occurrence["paths"]
    } == {
        ("WebApp", "Middle.Library", "Vulnerable.Library"),
        ("WorkerApp", "Vulnerable.Library"),
    }


def test_target_framework_versions_remain_separate(monkeypatch):
    project = "src/Core.csproj"
    report = _assets(
        {
            ".NETCoreApp,Version=v6.0": {"Core.Library/1.0.0": {"type": "package"}},
            ".NETCoreApp,Version=v8.0": {"Core.Library/2.0.0": {"type": "package"}},
        },
        {
            "net6.0": {"targetAlias": "net6.0", "dependencies": {
                "Core.Library": {"target": "Package", "version": "1.0.0"},
            }},
            "net8.0": {"targetAlias": "net8.0", "dependencies": {
                "Core.Library": {"target": "Package", "version": "2.0.0"},
            }},
        },
    )
    _install_assets(monkeypatch, {project: report})
    resolver = nuget_relationship_version_resolver.NuGetRelationshipVersionResolver(
        {project: "<Project />"}, dotnet_executable="dotnet"
    )

    result = resolver.resolve("core.library", project)

    assert result["version"] is None
    assert {item["version"] for item in result["occurrences"]} == {"1.0.0", "2.0.0"}
    assert {item["framework"] for item in result["occurrences"]} == {"net6.0", "net8.0"}


def test_nuget_lockfile_path_mapping_remains_available():
    assert ManifestTool.lockfile_path("nuget", "src/App.csproj") == "src/packages.lock.json"
    assert ManifestTool.relationship_resolver_kind("nuget", "src/packages.lock.json") == "nuget"


@pytest.mark.asyncio
async def test_package_relationship_resolver_uses_assets_for_nuget(monkeypatch):
    project = "src/App.csproj"
    report = _assets(
        {".NETCoreApp,Version=v8.0": {
            "WebApp/2.0.0": {"type": "package", "dependencies": {"Vulnerable.Library": "1.5.0"}},
            "Vulnerable.Library/1.5.0": {"type": "package"},
        }},
        {"net8.0": {"targetAlias": "net8.0", "dependencies": {
            "WebApp": {"target": "Package", "version": "2.0.0"},
        }}},
    )
    _install_assets(monkeypatch, {project: report})
    manifest_tool = ManifestTool(token="token")
    manifest_tool.repository_tree = AsyncMock(return_value=[{"path": project}])
    manifest_tool.get = AsyncMock(return_value="<Project />")
    item = SecurityPackageTriage(
        package="Vulnerable.Library",
        vulnerablility_version_range="<2.0.0",
        vulnerablility_fixed_version="2.0.0",
        ecosystem="nuget",
        manifest_path=project,
        istransitive=True,
    )

    await PackageRelationshipResolver(manifest_tool=manifest_tool).populate(
        "owner", "repo", [item], ref="snapshot"
    )

    manifest_tool.repository_tree.assert_awaited_once_with("owner", "repo", "snapshot")
    assert item.current_version == "1.5.0"
    assert item.transitive_dependency_occurrences[0].introducers[0].package == "WebApp"


@pytest.mark.asyncio
async def test_factory_uses_nuget_relationship_resolver():
    resolver = await RelationshipResolverFactory().create(
        "nuget",
        project_files={"src/App.csproj": "<Project />"},
    )

    assert isinstance(
        resolver,
        nuget_relationship_version_resolver.NuGetRelationshipVersionResolver,
    )


MODULE = "src.engines.resolvers.relationship_version_resolvers.nuget_relationship_version_resolver"


def _recording_run(monkeypatch, project_assets):
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        if command[1] == "--version":
            return subprocess.CompletedProcess(command, 0, stdout="10.0.100", stderr="")
        report = project_assets[command[2]]
        if report is None:
            return subprocess.CompletedProcess(command, 1, stdout="", stderr="restore failed")
        assets_path = Path(kwargs["cwd"]) / Path(command[2]).parent / "obj" / "project.assets.json"
        assets_path.parent.mkdir(parents=True, exist_ok=True)
        assets_path.write_text(json.dumps(report), encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(f"{MODULE}.subprocess.run", run)
    return calls


def _simple_report():
    return _assets(
        {".NETCoreApp,Version=v8.0": {
            "WebApp/2.0.0": {"type": "package", "dependencies": {"Lib.A": "1.0.0", "Lib.B": "1.0.0"}},
            "Lib.A/1.0.0": {"type": "package"},
            "Lib.B/1.0.0": {"type": "package"},
        }},
        {"net8.0": {"targetAlias": "net8.0", "dependencies": {
            "WebApp": {"target": "Package", "version": "2.0.0"},
        }}},
    )


def test_restore_environment_excludes_tokens_but_keeps_nuget_settings(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "secret")
    monkeypatch.setenv("NUGET_PACKAGES", "/cache")
    monkeypatch.setenv("NuGetPackageSourceCredentials_feed", "user:pw")
    calls = _recording_run(monkeypatch, {"src/App.csproj": _simple_report()})
    resolver = nuget_relationship_version_resolver.NuGetRelationshipVersionResolver(
        {"src/App.csproj": "<Project />"}, dotnet_executable="dotnet"
    )

    resolver.resolve("Lib.A")

    for _, kwargs in calls:
        env = {key.upper(): value for key, value in kwargs["env"].items()}
        assert "GITHUB_TOKEN" not in env
        assert env["NUGET_PACKAGES"] == "/cache"
        assert env["NUGETPACKAGESOURCECREDENTIALS_FEED"] == "user:pw"


@pytest.mark.parametrize("path", ["C:/x/App.csproj", "../App.csproj", "/abs/App.csproj"])
def test_staged_paths_cannot_leave_the_workspace(path):
    with pytest.raises(ValueError, match="Invalid repository path"):
        nuget_relationship_version_resolver.NuGetRelationshipVersionResolver(
            {path: "<Project />"}, dotnet_executable="dotnet"
        )


def test_restore_runs_once_per_project_across_targets_and_failures_are_not_retried(monkeypatch):
    calls = _recording_run(
        monkeypatch, {"src/App.csproj": _simple_report(), "src/Broken.csproj": None}
    )
    resolver = nuget_relationship_version_resolver.NuGetRelationshipVersionResolver(
        {"src/App.csproj": "<Project />", "src/Broken.csproj": "<Project />"},
        dotnet_executable="dotnet",
    )

    first = resolver.resolve("Lib.A")
    second = resolver.resolve("Lib.B")
    resolver.prefetch(["Lib.A", "Lib.B", "Missing"])

    restores = [command for command, _ in calls if command[1] == "restore"]
    assert len(restores) == 2
    assert first["complete"] is False
    assert second["occurrences"][0]["package"] == "Lib.B"
    assert resolver.resolve("Lib.B", "src/App.csproj")["complete"] is True


def test_path_limit_truncates_instead_of_failing(monkeypatch):
    monkeypatch.setattr(f"{MODULE}.MAX_PATHS_PER_TARGET", 1)
    report = _assets(
        {".NETCoreApp,Version=v8.0": {
            "App.A/1.0.0": {"type": "package", "dependencies": {"Shared": "1.0.0"}},
            "App.B/1.0.0": {"type": "package", "dependencies": {"Shared": "1.0.0"}},
            "Shared/1.0.0": {"type": "package"},
        }},
        {"net8.0": {"targetAlias": "net8.0", "dependencies": {
            "App.A": {"target": "Package"}, "App.B": {"target": "Package"},
        }}},
    )
    _recording_run(monkeypatch, {"src/App.csproj": report})
    resolver = nuget_relationship_version_resolver.NuGetRelationshipVersionResolver(
        {"src/App.csproj": "<Project />"}, dotnet_executable="dotnet"
    )

    result = resolver.resolve("Shared", "src/App.csproj")

    assert result["complete"] is True
    assert result["paths_truncated"] is True
    assert len(result["paths"]) == 1


def test_net_framework_aliases_match_their_target_names(monkeypatch):
    report = _assets(
        {
            ".NETFramework,Version=v4.8": {
                "Old.App/1.0.0": {"type": "package", "dependencies": {"Shared": "1.0.0"}},
                "Shared/1.0.0": {"type": "package"},
            },
            ".NETCoreApp,Version=v8.0": {"Shared/2.0.0": {"type": "package"}},
        },
        {
            "net48": {"targetAlias": "net48", "dependencies": {
                "Old.App": {"target": "Package"},
            }},
            "net8.0": {"targetAlias": "net8.0", "dependencies": {
                "Shared": {"target": "Package"},
            }},
        },
    )
    _recording_run(monkeypatch, {"src/App.csproj": report})
    resolver = nuget_relationship_version_resolver.NuGetRelationshipVersionResolver(
        {"src/App.csproj": "<Project />"}, dotnet_executable="dotnet"
    )

    by_framework = {
        item["framework"]: item for item in resolver.resolve("Shared")["occurrences"]
    }

    assert by_framework["net48"]["is_root"] is False
    assert [node["package"] for node in by_framework["net48"]["paths"][0]] == ["Old.App", "Shared"]
    assert by_framework["net8.0"]["is_root"] is True
