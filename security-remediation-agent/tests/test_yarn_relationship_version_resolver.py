import json
import subprocess
from unittest.mock import AsyncMock

import pytest

from src.engines.package_relationship_resolver import PackageRelationshipResolver

from src.engines.resolvers.relationship_version_resolvers import (
    yarn_relationship_version_resolver,
)


def _berry_tree():
    return json.dumps({
        "value": "app@workspace:.",
        "children": {
            "parent@npm:1.2.0": {
                "value": {
                    "locator": "parent@npm:1.2.0",
                    "descriptor": "parent@^1.0.0",
                },
                "children": {
                    "@scope/target@npm:4.2.1": {
                        "value": {
                            "locator": "@scope/target@npm:4.2.1",
                            "descriptor": "@scope/target@^4.0.0",
                        },
                    },
                },
            },
        },
    })


@pytest.mark.parametrize("chain,target,expected", [
    ("@fluentui#react-components#lodash", "lodash", ["@fluentui/react-components", "lodash"]),
    ("@playwright#test#playwright", "playwright", ["@playwright/test", "playwright"]),
    ("@typescript-eslint#parser#@scope#target", "@scope/target", ["@typescript-eslint/parser", "@scope/target"]),
    ("@fluentui/react-components#lodash", "lodash", ["@fluentui/react-components", "lodash"]),
])
def test_classic_hash_paths_preserve_scoped_package_names(chain, target, expected):
    output = json.dumps({"type": "info", "data": f'Hoisted from "{chain}"'})
    paths = yarn_relationship_version_resolver.YarnRelationshipVersionResolver._parse_classic_why(output, target)
    assert paths == [[(name, "") for name in expected]]


@pytest.mark.asyncio
async def test_yarn_resolver_receives_companion_manifest_and_resolves_parent(monkeypatch):
    files = {
        "webapp/yarn.lock": "__metadata:\n  version: 8\n",
        "webapp/package.json": json.dumps({
            "packageManager": "yarn@4.1.1",
            "dependencies": {"parent": "^1.0.0"},
        }),
    }
    tool = AsyncMock()
    tool.get.side_effect = lambda owner, repo, path, ref: files.get(path)
    monkeypatch.setattr(yarn_relationship_version_resolver.shutil, "which", lambda _: "yarn")
    monkeypatch.setattr(
        yarn_relationship_version_resolver.subprocess, "run",
        lambda command, **kwargs: subprocess.CompletedProcess(
            command, 0, stdout=_berry_tree(), stderr=""),
    )

    resolver = await PackageRelationshipResolver(manifest_tool=tool)._build_resolver(
        "owner", "repo", "yarn", "webapp/yarn.lock", "main",
    )

    assert resolver is not None
    tool.get.assert_any_await("owner", "repo", "webapp/package.json", "main")
    [occurrence] = resolver.resolve("@scope/target")["occurrences"]
    assert occurrence["version"] == "4.2.1"
    assert occurrence["introducers"] == [{"package": "parent", "version": "1.2.0"}]


def test_berry_uses_recursive_why_json_and_locator_versions(monkeypatch):
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout=_berry_tree(), stderr="")

    monkeypatch.setattr(
        "src.engines.resolvers.relationship_version_resolvers.yarn_relationship_version_resolver.subprocess.run",
        run,
    )
    resolver = yarn_relationship_version_resolver.YarnRelationshipVersionResolver(
        "__metadata:\n  version: 8\n",
        json.dumps({"packageManager": "yarn@4.1.1", "dependencies": {"parent": "^1.0.0"}}),
        yarn_executable="yarn",
    )

    result = resolver.resolve("@scope/target")

    assert calls == [["yarn", "why", "@scope/target", "--recursive", "--json"]]
    [occurrence] = result["occurrences"]
    assert occurrence["version"] == "4.2.1"
    assert occurrence["introducers"] == [{"package": "parent", "version": "1.2.0"}]
    assert occurrence["paths"] == [["parent@1.2.0", "@scope/target@4.2.1"]]
    assert yarn_relationship_version_resolver.YarnRelationshipVersionResolver._parse_locator(
        "target@patch:target@npm%3A4.2.1#optional!builtin<compat/target>"
    )[1] == "4.2.1"


def test_classic_uses_full_tree_from_declared_roots(monkeypatch):
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        if command[1] == "why":
            stdout = json.dumps({
                "type": "info",
                "data": 'This module exists because "parent#target" depends on it.',
            })
        else:
            stdout = json.dumps({
                "type": "tree",
                "data": {"trees": [
                    {"name": "parent@1.2.0", "children": [{"name": "target@4.2.1"}]},
                ]},
            })
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

    monkeypatch.setattr(
        "src.engines.resolvers.relationship_version_resolvers.yarn_relationship_version_resolver.subprocess.run",
        run,
    )
    resolver = yarn_relationship_version_resolver.YarnRelationshipVersionResolver(
        "# yarn lockfile v1\n",
        json.dumps({"packageManager": "yarn@1.22.22", "dependencies": {"parent": "^1.0.0"}}),
        yarn_executable="yarn",
    )

    result = resolver.resolve("target")

    assert calls == [["yarn", "list", "--json"]]


    [occurrence] = result["occurrences"]
    assert occurrence["version"] == "4.2.1"
    assert occurrence["introducers"] == [{"package": "parent", "version": "1.2.0"}]

def _classic(monkeypatch, run, package=None):
    monkeypatch.setattr(
        "src.engines.resolvers.relationship_version_resolvers.yarn_relationship_version_resolver.subprocess.run",
        run,
    )
    return yarn_relationship_version_resolver.YarnRelationshipVersionResolver(
        "# yarn lockfile v1\n",
        json.dumps(package or {"packageManager": "yarn@1.22.22", "dependencies": {"parent": "^2.0.0"}}),
        yarn_executable="yarn",
    )


def test_package_not_found_is_empty_and_does_not_abort_other_targets(monkeypatch):
    def run(command, **kwargs):
        if command[1] == "why" and command[2] == "missing":
            return subprocess.CompletedProcess(command, 1, stdout="", stderr="error We couldn't find a match!")
        if command[1] == "why":
            data = 'This module exists because "parent#present" depends on it.'
            return subprocess.CompletedProcess(command, 0, stdout=json.dumps({"type": "info", "data": data}), stderr="")
        tree = {"type": "tree", "data": {"trees": [{"name": "present@1.0.0"}, {"name": "parent@2.0.0", "children": [{"name": "present@^1.0.0", "shadow": True}]}]}}
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps(tree), stderr="")

    resolver = _classic(monkeypatch, run)
    resolver.prefetch(["missing", "present"])
    assert resolver.resolve("missing")["occurrences"] == []
    assert resolver.resolve("present")["occurrences"][0]["version"] == "1.0.0"


def test_real_yarn_failure_still_raises(monkeypatch):
    import pytest

    def run(command, **kwargs):
        return subprocess.CompletedProcess(command, 1, stdout="", stderr="error Lockfile corrupted")

    with pytest.raises(subprocess.SubprocessError):
        _classic(monkeypatch, run).prefetch(["target"])


def test_peer_dependency_is_not_a_root_and_invalid_names_never_run(monkeypatch):
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps({"type": "tree", "data": {"trees": []}}), stderr="")

    resolver = _classic(monkeypatch, run, {"packageManager": "yarn@1.22.22", "peerDependencies": {"react": "^18"}})
    assert resolver.resolve("react")["occurrences"] == []
    assert resolver.resolve("--cwd")["occurrences"] == []
    assert all("--cwd" not in call for call in calls)


def test_hoisted_and_nested_versions_retain_declared_root_paths(monkeypatch):
    trees = [
        {"name": "react-scripts@5.0.1", "children": [
            {"name": "jest-util@^27.0.0", "shadow": True},
        ]},
        {"name": "@scope/tools@2.0.0", "children": [
            {"name": "jest-util@28.1.3", "children": [
                {"name": "picomatch@3.0.0"},
            ]},
        ]},
        {"name": "jest-util@27.5.1", "children": [
            {"name": "picomatch@^2.3.1", "shadow": True},
            {"name": "react-scripts@^5", "shadow": True},  # cycle
        ]},
        {"name": "picomatch@2.3.1"},
        {"name": "orphan@1.0.0", "children": [
            {"name": "picomatch@2.0.0"},  # not reachable from declarations
        ]},
    ]
    calls = []
    def run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps({
            "type": "tree", "data": {"trees": trees}}), stderr="")
    resolver = _classic(monkeypatch, run, {"dependencies": {
        "react-scripts": "5.0.1", "@scope/tools": "2.0.0"}})
    resolver.prefetch(["picomatch", "jest-util"])
    occurrences = resolver.resolve("picomatch")["occurrences"]
    by_version = {o["version"]: o for o in occurrences}
    assert set(by_version) == {"2.3.1", "3.0.0"}
    assert by_version["2.3.1"]["introducers"] == [{"package": "react-scripts", "version": "5.0.1"}]
    assert by_version["2.3.1"]["paths"] == [["react-scripts@5.0.1", "jest-util@27.5.1", "picomatch@2.3.1"]]
    assert by_version["3.0.0"]["paths"] == [["@scope/tools@2.0.0", "jest-util@28.1.3", "picomatch@3.0.0"]]
    assert calls == [["yarn", "list", "--json"]]


    from src.engines.grouping import UpgradeTargetBuilder
    from src.models.security_package_triage import SecurityPackageTriage
    finding = SecurityPackageTriage(package="picomatch", ecosystem="npm", istransitive=True,
        manifest_path="yarn.lock", vulnerablility_version_range="<2.3.2", vulnerablility_fixed_version="2.3.2")
    PackageRelationshipResolver._add_transitive_occurrences(
        finding, resolver.resolve("picomatch"), "yarn.lock", vulnerable_range="<2.3.2", fixed_version="2.3.2")
    targets = UpgradeTargetBuilder.build([finding])
    assert {t["package"] for t in targets} == {"react-scripts"}
    assert targets[0]["current_version"] == "5.0.1"


def test_invalid_tree_is_not_silently_cached_as_no_findings(monkeypatch):
    def run(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, stdout="not a tree", stderr="")
    with pytest.raises(ValueError, match="dependency tree"):
        _classic(monkeypatch, run).resolve("picomatch")
