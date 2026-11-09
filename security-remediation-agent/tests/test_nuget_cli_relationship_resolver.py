import json
import subprocess
from pathlib import Path

from src.engines.package_relationship_resolver import PackageRelationshipResolver
from src.engines.resolvers.relationship_version_resolvers import (
    nuget_relationship_version_resolver,
)
from src.models.security_package_triage import (
    OccurrenceClassification,
    SecurityPackageTriage,
)


def test_keeps_assets_path_when_an_unrelated_project_restore_fails(monkeypatch):
    project_path = "api/Unified.UserManagement/Unified.UserManagement.csproj"
    broken_path = "tests/Legacy.Tests.csproj"
    assets = {
        "targets": {
            ".NETCoreApp,Version=v10.0": {
                "Microsoft.IdentityModel/8.0.1": {
                    "type": "package",
                    "dependencies": {"System.Security.Cryptography.Pkcs": "8.0.1"},
                },
                "System.Security.Cryptography.Pkcs/8.0.1": {"type": "package"},
            },
        },
        "project": {
            "frameworks": {
                "net10.0": {
                    "targetAlias": "net10.0",
                    "dependencies": {
                        "Microsoft.IdentityModel": {"target": "Package", "version": "8.0.1"},
                    },
                },
            },
        },
    }

    def run(command, **kwargs):
        if command[1] == "--version":
            return subprocess.CompletedProcess(command, 0, stdout="10.0.100", stderr="")
        if command[1] == "restore" and command[2] == broken_path:
            return subprocess.CompletedProcess(command, 1, stdout="", stderr="restore failed")
        if command[1] == "restore":
            assets_path = (
                Path(kwargs["cwd"])
                / Path(command[2]).parent
                / "obj"
                / "project.assets.json"
            )
            assets_path.parent.mkdir(parents=True, exist_ok=True)
            assets_path.write_text(json.dumps(assets), encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
        raise AssertionError(f"Unexpected dotnet command: {command}")

    monkeypatch.setattr(
        "src.engines.resolvers.relationship_version_resolvers.nuget_relationship_version_resolver.subprocess.run",
        run,
    )
    resolver = nuget_relationship_version_resolver.NuGetRelationshipVersionResolver(
        {project_path: "<Project />", broken_path: "<Project />"},
        dotnet_executable="dotnet",
    )
    resolver.prefetch(["System.Security.Cryptography.Pkcs"])
    result = resolver.resolve("System.Security.Cryptography.Pkcs", project_path)

    assert result["version"] == "8.0.1"
    assert result["complete"] is True
    [resolved_occurrence] = result["occurrences"]
    assert [node["package"] for node in resolved_occurrence["paths"][0]] == [
        "Microsoft.IdentityModel",
        "System.Security.Cryptography.Pkcs",
    ]
    assert resolved_occurrence["is_root"] is False

    triage = SecurityPackageTriage(
        package="System.Security.Cryptography.Pkcs",
        ecosystem="nuget",
        manifest_path=project_path,
        vulnerablility_version_range=">= 8.0.0, <= 8.0.1",
        vulnerablility_fixed_version="8.0.2",
        istransitive=True,
    )
    PackageRelationshipResolver._add_transitive_occurrences(
        triage,
        result,
        project_path,
    )

    assert triage.current_version == "8.0.1"
    [occurrence] = triage.transitive_dependency_occurrences
    assert occurrence.classification == OccurrenceClassification.TRANSITIVE


def test_resolve_emits_project_framework_and_introducer_extraction_schema(monkeypatch):
    project_path = "api/Unified.UserManagement/Unified.UserManagement.csproj"
    assets = {
        "targets": {
            ".NETCoreApp,Version=v10.0": {
                "ParentPackage/1.0.0": {
                    "type": "package",
                    "dependencies": {"IntermediatePackage": "2.0.0"},
                },
                "IntermediatePackage/2.0.0": {
                    "type": "package",
                    "dependencies": {"System.Security.Cryptography.Pkcs": "8.0.1"},
                },
                "System.Security.Cryptography.Pkcs/8.0.1": {"type": "package"},
            },
        },
        "project": {
            "frameworks": {
                "net10.0": {
                    "targetAlias": "net10.0",
                    "dependencies": {
                        "ParentPackage": {"target": "Package", "version": "1.0.0"},
                    },
                },
            },
        },
    }

    def run(command, **kwargs):
        if command[1] == "--version":
            return subprocess.CompletedProcess(command, 0, stdout="10.0.100", stderr="")
        if command[1] == "restore":
            assets_path = (
                Path(kwargs["cwd"])
                / Path(command[2]).parent
                / "obj"
                / "project.assets.json"
            )
            assets_path.parent.mkdir(parents=True, exist_ok=True)
            assets_path.write_text(json.dumps(assets), encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
        raise AssertionError(f"Unexpected dotnet command: {command}")

    monkeypatch.setattr(
        "src.engines.resolvers.relationship_version_resolvers.nuget_relationship_version_resolver.subprocess.run",
        run,
    )
    resolver = nuget_relationship_version_resolver.NuGetRelationshipVersionResolver(
        {project_path: "<Project />"},
        dotnet_executable="dotnet",
    )

    extracted = resolver.resolve("System.Security.Cryptography.Pkcs", project_path)

    assert extracted["project"] == "Unified.UserManagement"
    assert extracted["framework"] == "net10.0"
    assert extracted["target"] == "System.Security.Cryptography.Pkcs"
    assert extracted["paths"] == [{
        "directIntroducer": "ParentPackage",
        "immediateIntroducer": "IntermediatePackage",
        "packages": [
            {"name": "ParentPackage", "version": "1.0.0"},
            {"name": "IntermediatePackage", "version": "2.0.0"},
            {"name": "System.Security.Cryptography.Pkcs", "version": "8.0.1"},
        ],
    }]