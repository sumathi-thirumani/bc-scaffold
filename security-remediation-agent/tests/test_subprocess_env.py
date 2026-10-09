import subprocess
import threading
from types import SimpleNamespace

import pytest

from src.engines.recommendation_resolver.pip_parent_version_resolver import (
    ParentCandidate,
    ParentVersionShortlister,
    PipParentVersionResolver,
)
from src.agents import vulnerability_reviewer_agent as reviewer_module
from src.agents.vulnerability_reviewer_agent import NCU_VERSION, VulnerabilityReviewerAgent
from src.utils.subprocess_env import minimal_subprocess_env


def test_minimal_env_excludes_credentials(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "secret")
    monkeypatch.setenv("NPM_TOKEN", "secret")
    monkeypatch.setenv("PATH", "/usr/bin")

    env = minimal_subprocess_env({"NO_COLOR": "1"})

    assert "GITHUB_TOKEN" not in env
    assert "NPM_TOKEN" not in env
    assert env["PATH"] == "/usr/bin"
    assert env["NO_COLOR"] == "1"


def test_npm_check_updates_is_pinned_and_gets_no_token(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "secret")
    monkeypatch.setattr(reviewer_module.shutil, "which", lambda name: "npx")
    captured = {}

    def fake_run(args, **kwargs):
        captured["args"] = args
        captured["env"] = kwargs["env"]
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr(reviewer_module.subprocess, "run", fake_run)

    VulnerabilityReviewerAgent._run_npm_check_updates('{"dependencies": {}}')

    assert f"npm-check-updates@{NCU_VERSION}" in captured["args"]
    assert "GITHUB_TOKEN" not in captured["env"]


class _Shortlister:
    async def shortlist(self, *args):
        return [ParentCandidate(version="2.0.0")]


class _Verifier:
    def __init__(self):
        self.thread = None

    def verify(self, parent, version, child, safe_child_version):
        self.thread = threading.current_thread()
        return safe_child_version


@pytest.mark.asyncio
async def test_pip_shortlist_is_ascending_and_skips_current_and_older():
    class Pypi:
        async def list_versions_descending(self, name):
            return ["3.0.0", "2.2.0", "2.1.0", "2.0.0", "1.9.0"]

        async def get_release_requires_dist(self, name, version):
            return []

    shortlister = ParentVersionShortlister(Pypi(), max_candidates=3)

    candidates = await shortlister.shortlist("parent", "child", "1.5.0", "2.0.0")

    assert [c.version for c in candidates] == ["2.1.0", "2.2.0", "3.0.0"]


@pytest.mark.asyncio
async def test_pip_shortlist_tolerates_invalid_versions_and_specifiers():
    class Pypi:
        async def list_versions_descending(self, name):
            return ["2.0.0", "1.0.0"]

        async def get_release_requires_dist(self, name, version):
            return ["child (>>bogus)"] if version == "2.0.0" else []

    shortlister = ParentVersionShortlister(Pypi())

    assert await shortlister.shortlist("parent", "child", "not-a-version") == []
    candidates = await shortlister.shortlist("parent", "child", "1.5.0", "garbage")
    assert [c.version for c in candidates] == ["1.0.0", "2.0.0"]


@pytest.mark.asyncio
async def test_pypi_metadata_is_downloaded_once_per_package():
    from src.engines.recommendation_resolver.pip_parent_version_resolver import PyPiMetadataClient

    calls = []

    class Response:
        def raise_for_status(self):
            pass

        def json(self):
            return {"info": {"version": "2.0.0", "requires_dist": []},
                    "releases": {"1.0.0": [{}], "2.0.0": [{}]}}

    class Client:
        async def get(self, url):
            calls.append(url)
            return Response()

    pypi = PyPiMetadataClient(Client())
    await pypi.list_versions_descending("Parent")
    await pypi.get_release_requires_dist("parent", "2.0.0")
    await pypi.list_versions_descending("parent")

    assert len(calls) == 1


@pytest.mark.asyncio
async def test_pip_resolver_returns_minimum_verified_parent_version():
    class Pypi:
        async def list_versions_descending(self, name):
            return ["3.0.0", "2.2.0", "2.1.0", "2.0.0"]

        async def get_release_requires_dist(self, name, version):
            return []

    class Verifier:
        def verify(self, parent, version, child, safe):
            return safe if version in {"2.2.0", "3.0.0"} else None

    resolver = PipParentVersionResolver(
        shortlister=ParentVersionShortlister(Pypi()), verifier=Verifier()
    )

    resolution = await resolver.resolve("parent", "child", "1.5.0", "2.0.0")

    assert resolution.resolved_version == "2.2.0"
    assert resolution.minimum_upgradable_version == "2.2.0"


@pytest.mark.asyncio
async def test_pip_verifier_runs_off_the_event_loop_thread():
    verifier = _Verifier()
    resolver = PipParentVersionResolver(shortlister=_Shortlister(), verifier=verifier)

    resolution = await resolver.resolve("parent", "child", "1.5.0", "1.0.0")

    assert resolution.resolved_version == "2.0.0"
    assert verifier.thread is not threading.main_thread()
