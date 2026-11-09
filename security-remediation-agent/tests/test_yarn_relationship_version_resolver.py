import json
import subprocess

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
        json.dumps({"packageManager": "yarn@4.1.1"}),
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


def test_classic_uses_why_json_without_recursive_and_list_for_versions(monkeypatch):
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
        json.dumps({"packageManager": "yarn@1.22.22"}),
        yarn_executable="yarn",
    )

    result = resolver.resolve("target")

    assert calls[0] == ["yarn", "why", "target", "--json"]
    assert calls[1][1:3] == ["list", "--pattern"]
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
        json.dumps(package or {"packageManager": "yarn@1.22.22"}),
        yarn_executable="yarn",
    )


def test_package_not_found_is_empty_and_does_not_abort_other_targets(monkeypatch):
    def run(command, **kwargs):
        if command[1] == "why" and command[2] == "missing":
            return subprocess.CompletedProcess(command, 1, stdout="", stderr="error We couldn't find a match!")
        if command[1] == "why":
            data = 'This module exists because "parent#present" depends on it.'
            return subprocess.CompletedProcess(command, 0, stdout=json.dumps({"type": "info", "data": data}), stderr="")
        tree = {"type": "tree", "data": {"trees": [{"name": "present@1.0.0"}, {"name": "parent@2.0.0"}]}}
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


def test_multiple_installed_versions_are_not_guessed(monkeypatch):
    def run(command, **kwargs):
        if command[1] == "why":
            data = 'This module exists because "parent#target" depends on it.'
            return subprocess.CompletedProcess(command, 0, stdout=json.dumps({"type": "info", "data": data}), stderr="")
        tree = {"type": "tree", "data": {"trees": [{"name": "target@1.0.0"}, {"name": "target@2.0.0"}]}}
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps(tree), stderr="")

    [occurrence] = _classic(monkeypatch, run).resolve("target")["occurrences"]
    assert occurrence["version"] is None


def test_peer_dependency_is_not_a_root_and_invalid_names_never_run(monkeypatch):
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    resolver = _classic(monkeypatch, run, {"packageManager": "yarn@1.22.22", "peerDependencies": {"react": "^18"}})
    assert resolver.resolve("react")["occurrences"] == []
    assert resolver.resolve("--cwd")["occurrences"] == []
    assert all("--cwd" not in call for call in calls)
