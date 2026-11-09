import subprocess
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from src.engines.reviewers import npm_compatible_version_reviewer as module
from src.engines.reviewers.npm_compatible_version_reviewer import (
    NpmCheckUpdatesResult,
    NpmCompatibleVersionReviewer,
)
from src.models.security_package_triage import PackageUpgradeRecommendation


def _plan(*names):
    recommendations = [PackageUpgradeRecommendation(package=n, from_version="1.0.0") for n in names]
    triage = SimpleNamespace(
        ecosystem="npm",
        manifest_path="web/package.json",
        compatible_versions={},
        package_upgrade_recommendations=recommendations,
    )
    bundle = SimpleNamespace(groupName="g", packages=[triage])
    return SimpleNamespace(remediation_plan_bundles=[bundle]), recommendations


def _reviewer(text='{"dependencies": {}}'):
    tool = SimpleNamespace(get=AsyncMock(return_value=text))
    return NpmCompatibleVersionReviewer(tool)


def _ncu(upgrades, declared, returncode=0):
    process = subprocess.CompletedProcess([], returncode, stdout="", stderr="boom")
    return NpmCheckUpdatesResult(process=process, upgrades=upgrades, declared_versions=declared)


async def _review(monkeypatch, reviewer, plan, outcome):
    def fake(_text, _names):
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    monkeypatch.setattr(NpmCompatibleVersionReviewer, "_run_npm_check_updates", staticmethod(fake))
    await reviewer.review(plan, {"owner": "o", "repo": "r"})


async def test_statuses_are_reported_per_package(monkeypatch):
    plan, (found, unchanged, rejected, undeclared) = _plan("a", "b", "bootstrap", "c")
    outcome = _ncu(
        {"a": "^2.1.0"},
        {"a": "^1.0.0", "b": "^1.0.0", "bootstrap": "^4.0.0"},
    )

    await _review(monkeypatch, _reviewer(), plan, outcome)

    triage = plan.remediation_plan_bundles[0].packages[0]
    assert (found.compatible_review_status, triage.compatible_versions["a"]) == ("upgrade_found", "2.1.0")
    assert unchanged.compatible_review_status == "no_upgrade"
    assert rejected.compatible_review_status == "no_upgrade"
    assert "bootstrap" not in triage.compatible_versions
    assert undeclared.compatible_review_status == "not_declared"


@pytest.mark.parametrize(
    "outcome",
    [
        subprocess.TimeoutExpired("npx", 300),
        RuntimeError("npx is required for npm package review"),
        ValueError("Expecting value"),
        _ncu({}, {}, returncode=1),
    ],
)
async def test_failures_flag_recommendations_instead_of_raising(monkeypatch, outcome):
    plan, (recommendation,) = _plan("a")

    await _review(monkeypatch, _reviewer(), plan, outcome)

    assert recommendation.compatible_review_status == "review_failed"


async def test_unfetchable_manifest_is_flagged(monkeypatch):
    plan, (recommendation,) = _plan("a")

    await _review(monkeypatch, _reviewer(text=None), plan, _ncu({}, {}))

    assert recommendation.compatible_review_status == "review_failed"


@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        ("^1.2.3", "1.2.3"),
        ("~1.2.3", "1.2.3"),
        ("v1.2.3", "1.2.3"),
        (">=1.2.3", "1.2.3"),
        ("1.2.3-beta.1", "1.2.3-beta.1"),
        ("<1.2.3", None),
        (">=1.0.0 <2.0.0", None),
        ("^1.0.0 || ^2.0.0", None),
        ("npm:other@1.2.3", None),
        ("workspace:^1.2.3", None),
        ("git+https://example.com/x.git#1.2.3", None),
        ("*", None),
    ],
)
def test_only_simple_ranges_yield_a_version(spec, expected):
    assert NpmCompatibleVersionReviewer._single_version(spec) == expected


def test_reject_list_comes_from_the_constant(monkeypatch):
    captured = {}
    monkeypatch.setattr(module.shutil, "which", lambda name: "npx")

    def fake_run(command, **kwargs):
        captured["command"] = command
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(module.subprocess, "run", fake_run)

    NpmCompatibleVersionReviewer._run_npm_check_updates('{"dependencies": {}}', {"a"})

    command = captured["command"]
    assert command[command.index("--reject") + 1] == ",".join(sorted(module.NCU_REJECTED_PACKAGES))
