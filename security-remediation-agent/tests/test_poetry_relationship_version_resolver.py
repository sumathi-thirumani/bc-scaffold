import subprocess
from types import SimpleNamespace

import pytest

from src.engines.package_relationship_resolver import PackageRelationshipResolver
from src.engines.resolvers.relationship_version_resolvers import (
    poetry_relationship_version_resolver as module,
)
from src.engines.resolvers.relationship_version_resolvers.poetry_relationship_version_resolver import (
    PoetryRelationshipVersionResolver,
    direct_declarations,
    parse_why_output,
)

PROJECT = """
[tool.poetry.dependencies]
python = "^3.10"
boto3 = "^1.34"
requests = "^2.31"
numpy = [{version = "^1.0", python = "<3.10"}, {version = "^2.0", python = ">=3.10"}]
"""

LOCK = """
[[package]]
name = "boto3"
version = "1.43.126"
[[package]]
name = "botocore"
version = "1.43.126"
[[package]]
name = "requests"
version = "2.34.2"
[[package]]
name = "urllib3"
version = "2.8.0"
"""

OUTPUTS = {
    "urllib3": (
        "botocore 1.43.126 Low-level core.\n"
        "`-- urllib3 >=1.25.4,!=2.2.0,<3\n"
        "requests 2.34.2 Python HTTP for Humans.\n"
        "`-- urllib3 >=1.26,<3\n"
    ),
    "botocore": (
        "boto3 1.43.126 The AWS SDK\n"
        "`-- botocore >=1.43.126,<1.44.0\n"
        "    |-- jmespath >=0.7.1,<2.0.0 \n"
        "    `-- urllib3 >=1.25.4,!=2.2.0,<3 \n"
    ),
    "requests": "Package requests is a direct dependency.\n",
}


@pytest.fixture
def poetry_calls(monkeypatch):
    calls = []

    def fake_run(arguments, **kwargs):
        calls.append(arguments)
        name = arguments[arguments.index("show") + 1]
        if name not in OUTPUTS:
            return SimpleNamespace(returncode=1, stdout="", stderr=f"Package {name} not found")
        return SimpleNamespace(returncode=0, stdout=OUTPUTS[name], stderr="")

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    return calls


def resolver(**kwargs):
    return PoetryRelationshipVersionResolver(LOCK, PROJECT, poetry_command=["poetry"], **kwargs)


def test_parse_keeps_only_the_target_constraint_of_each_requirer():
    parents = parse_why_output(OUTPUTS["botocore"] + OUTPUTS["urllib3"], "urllib3")

    assert parents[0] == ("boto3", "1.43.126", None)
    assert ("botocore", "1.43.126", ">=1.25.4,!=2.2.0,<3") in parents
    assert parse_why_output(OUTPUTS["requests"], "requests") == []


def test_direct_declarations_read_all_sources_and_list_constraints():
    project = {
        "project": {"dependencies": ["Requests>=2 ; python_version>'3.8'", "not a req!!"]},
        "tool": {"poetry": {
            "dependencies": {"python": "^3.10", "numpy": [{"version": "^1"}, {"version": "^2"}]},
            "group": {"dev": {"dependencies": {"pytest": "*"}}},
        }},
        "dependency-groups": {"lint": ["ruff", {"include-group": "dev"}]},
    }

    declared = direct_declarations(project)

    assert set(declared) == {"requests", "numpy", "pytest", "ruff"}
    assert [item["version"] for item in declared["numpy"]] == ["^1", "^2"]
    assert declared["pytest"][0]["origin"] == "tool.poetry.group.dev"


def test_walks_requirers_upward_to_direct_dependencies(poetry_calls):
    occurrence = resolver().resolve("URLLIB3")["occurrences"][0]

    assert occurrence["version"] == "2.8.0"
    assert occurrence["is_root"] is False
    paths = [[node["package"] for node in path] for path in occurrence["paths"]]
    assert sorted(paths) == [["boto3", "botocore", "urllib3"], ["requests", "urllib3"]]
    boto_path = next(path for path in occurrence["paths"] if path[0]["package"] == "boto3")
    assert boto_path[-1]["dependency_conditions"] == [{"version": ">=1.25.4,!=2.2.0,<3"}]
    assert [node["package"] for node in occurrence["introducers"]] == ["boto3", "requests"]
    # Direct ancestors are not queried.
    assert [call[call.index("show") + 1] for call in poetry_calls] == ["urllib3", "botocore"]


def test_result_feeds_path_conversion(poetry_calls):
    occurrence = resolver().resolve("urllib3")["occurrences"][0]

    paths = PackageRelationshipResolver._dependency_paths(occurrence["paths"])

    assert sorted((node.package, node.version) for node in paths[0]) == sorted(
        (node["package"], node["version"]) for node in occurrence["paths"][0]
    )


def test_direct_target_is_root_and_results_are_cached(poetry_calls):
    instance = resolver()

    occurrence = instance.resolve("requests")["occurrences"][0]
    instance.resolve("requests")

    assert occurrence["is_root"] is True
    assert occurrence["declared_in"] == ["tool.poetry.dependencies"]
    assert [[node["package"] for node in path] for path in occurrence["paths"]] == [["requests"]]
    assert len(poetry_calls) == 1


def test_package_missing_from_lock_or_invalid_name_runs_no_poetry(poetry_calls):
    instance = resolver()

    assert instance.resolve("absent")["occurrences"] == []
    assert instance.resolve("bad name; rm")["occurrences"] == []
    assert poetry_calls == []


def test_poetry_failure_raises_subprocess_error(monkeypatch):
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=2, stdout="", stderr="boom"),
    )

    with pytest.raises(subprocess.SubprocessError, match="boom"):
        resolver().prefetch(["urllib3"])


def test_call_budget_truncates_instead_of_failing(poetry_calls):
    occurrence = resolver(max_calls=1).resolve("urllib3")["occurrences"][0]

    assert occurrence["paths_truncated"] is True
    assert [[node["package"] for node in path] for path in occurrence["paths"]] == [
        ["requests", "urllib3"],
    ]


def test_missing_cli_raises_os_error(monkeypatch):
    monkeypatch.setattr(module.shutil, "which", lambda name: None)
    monkeypatch.setattr(module.importlib.util, "find_spec", lambda name: None)

    with pytest.raises(OSError):
        PoetryRelationshipVersionResolver(LOCK, PROJECT)
