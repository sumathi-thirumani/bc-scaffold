import json
import subprocess

import pytest

from src.engines.resolvers.relationship_version_resolvers import npm_relationship_version_resolver as module
from src.engines.resolvers.relationship_version_resolvers.npm_relationship_version_resolver import (
    NpmRelationshipVersionResolver,
)


def _resolver():
    return NpmRelationshipVersionResolver("{}", "{}", npm_executable="npm")


def _fake_run(payload, returncode=0, calls=None):
    def run(cmd, **kwargs):
        if calls is not None:
            calls.append(cmd)
        return subprocess.CompletedProcess(cmd, returncode, json.dumps(payload), "")
    return run


def test_transitive_paths_versions_and_numeric_ordering(monkeypatch):
    tree = {"dependencies": {
        "app-a": {"version": "1.0.0", "dependencies": {"lodash": {"version": "10.0.0"}}},
        "app-b": {"version": "2.0.0", "dependencies": {"lodash": {"version": "9.0.0"}}},
        "lodash": {"version": "9.0.0"},
    }}
    monkeypatch.setattr(module.subprocess, "run", _fake_run(tree, returncode=1))
    result = _resolver().resolve("lodash")
    assert [o["version"] for o in result["occurrences"]] == ["9.0.0", "10.0.0"]
    nine, ten = result["occurrences"]
    assert nine["is_root"] and {i["package"] for i in nine["introducers"]} == {"app-b"}
    assert ten["paths"] == [["app-a@1.0.0", "lodash@10.0.0"]]


def test_missing_nodes_are_ignored(monkeypatch):
    tree = {"dependencies": {"lodash": {"missing": True}}}
    monkeypatch.setattr(module.subprocess, "run", _fake_run(tree, returncode=1))
    assert _resolver().resolve("lodash")["occurrences"] == []


def test_npm_error_raises_and_is_not_cached(monkeypatch):
    resolver = _resolver()
    monkeypatch.setattr(module.subprocess, "run", _fake_run({"error": {"code": "EJSONPARSE"}}, returncode=1))
    with pytest.raises(subprocess.SubprocessError):
        resolver.prefetch(["lodash"])
    assert "lodash" not in resolver._results

    monkeypatch.setattr(module.subprocess, "run", _fake_run({"dependencies": {"lodash": {"version": "1.0.0"}}}))
    assert resolver.resolve("lodash")["occurrences"][0]["version"] == "1.0.0"


def test_invalid_names_never_reach_npm(monkeypatch):
    calls = []
    monkeypatch.setattr(module.subprocess, "run", _fake_run({}, calls=calls))
    resolver = _resolver()
    resolver.prefetch(["--registry=evil", "a&calc", "@scope/pkg"])
    assert len(calls) == 1
    assert "@scope/pkg" in calls[0] and "--registry=evil" not in calls[0] and "a&calc" not in calls[0]
    assert resolver.resolve("a&calc")["occurrences"] == []
    assert {"--offline", "--ignore-scripts"} <= set(calls[0])


def test_path_enumeration_is_capped(monkeypatch):
    deps = {f"p{i}": {"version": "1.0.0", "dependencies": {"lodash": {"version": "1.0.0"}}}
            for i in range(module.MAX_PATHS_PER_TARGET + 50)}
    monkeypatch.setattr(module.subprocess, "run", _fake_run({"dependencies": deps}))
    paths = _resolver().resolve("lodash")["occurrences"][0]["paths"]
    assert len(paths) == module.MAX_PATHS_PER_TARGET
