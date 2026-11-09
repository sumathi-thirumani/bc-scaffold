import httpx
import pytest

from src.engines.resolvers.recommendation_resolver.pip_recommendation_resolver import (
    PipParentVersionResolver,
    PyPiMetadataClient,
)


def release(requires=None, yanked=False):
    return [{"yanked": yanked}], requires or []


def registry(packages, status=None, calls=None):
    """packages: name -> {version: (files, requires_dist)}."""
    status = status or {}

    def handler(request):
        parts = request.url.path.strip("/").split("/")[1:-1]
        name = parts[0]
        if calls is not None:
            calls.append(request.url.path)
        if name in status:
            return httpx.Response(status[name])
        versions = packages[name]
        if len(parts) == 2:
            return httpx.Response(200, json={"info": {"requires_dist": versions[parts[1]][1]}})
        return httpx.Response(200, json={
            "info": {"version": "0"},
            "releases": {v: files for v, (files, _) in versions.items()},
        })

    return httpx.MockTransport(handler)


async def resolve(packages, *, status=None, paths=None, current="1.0.0", fixed="2.0.0", calls=None, rng=None):
    async with httpx.AsyncClient(transport=registry(packages, status, calls)) as client:
        resolver = PipParentVersionResolver(pypi=PyPiMetadataClient(client, retry_delay=0))
        return await resolver.resolve(
            "app", "vuln", fixed, current, dependency_paths=paths, vulnerable_range=rng,
        )


VULN = {"1.0": release(), "2.0.0": release()}


@pytest.mark.asyncio
async def test_lowest_safe_release_above_current():
    packages = {
        "app": {"1.0.0": release(["vuln>=1"]), "1.1.0": release(["vuln>=1,<2"]),
                "1.2.0": release(["vuln>=2"]), "1.3.0": release(["vuln>=2"])},
        "vuln": VULN,
    }
    result = await resolve(packages)
    assert result.qualifying_upgrade_versions == ["1.2.0", "1.3.0"]
    assert result.resolved_version == result.minimum_upgradable_version == "1.2.0"


@pytest.mark.asyncio
async def test_fetch_failure_is_not_reported_as_no_safe_release():
    result = await resolve({"app": {}, "vuln": VULN}, status={"app": 503})
    assert result.action == "metadata_unavailable"
    assert not result.resolved


@pytest.mark.asyncio
async def test_release_requirement_fetch_failure_is_unavailable():
    packages = {"app": {"1.1.0": release(["vuln>=2"])}, "vuln": VULN}
    result = await resolve(packages, status={"vuln": 500})
    assert result.action == "metadata_unavailable"


@pytest.mark.asyncio
async def test_mutually_exclusive_markers_are_not_anded():
    packages = {
        "app": {"1.1.0": release(['vuln>=2; python_version < "3.11"', 'vuln>=2.0.0; python_version >= "3.11"'])},
        "vuln": VULN,
    }
    assert (await resolve(packages)).resolved_version == "1.1.0"


@pytest.mark.asyncio
async def test_unsafe_marker_branch_rejects_release():
    packages = {
        "app": {"1.1.0": release(['vuln>=2; sys_platform == "linux"', 'vuln<2; sys_platform == "win32"'])},
        "vuln": VULN,
    }
    assert (await resolve(packages)).action == "manual_remediation"


@pytest.mark.asyncio
async def test_extras_only_requirements_are_ignored():
    packages = {"app": {"1.1.0": release(['vuln<2; extra == "old"'])}, "vuln": VULN}
    assert (await resolve(packages)).resolved_version == "1.1.0"


@pytest.mark.asyncio
async def test_cycle_and_diamond_terminate_without_repeat_fetches():
    packages = {
        "app": {"1.1.0": release(["a>=1", "b>=1"])},
        "a": {"1.0.0": release(["b>=1", "vuln>=2"])},
        "b": {"1.0.0": release(["a>=1", "vuln>=2"])},
        "vuln": VULN,
    }
    paths = [
        [{"package": "app"}, {"package": "a"}, {"package": "vuln"}],
        [{"package": "app"}, {"package": "b"}, {"package": "vuln"}],
        [{"package": "app"}, {"package": "a"}, {"package": "b"}, {"package": "vuln"}],
        [{"package": "app"}, {"package": "b"}, {"package": "a"}, {"package": "vuln"}],
    ]
    calls = []
    result = await resolve(packages, paths=paths, calls=calls)
    assert result.resolved_version == "1.1.0"
    assert len(calls) == len(set(calls))


@pytest.mark.asyncio
async def test_partly_yanked_release_is_kept_but_fully_yanked_is_dropped():
    packages = {
        "app": {"1.1.0": ([{"yanked": True}, {"yanked": False}], ["vuln>=2"]),
                "1.2.0": ([{"yanked": True}], ["vuln>=2"])},
        "vuln": VULN,
    }
    assert (await resolve(packages)).qualifying_upgrade_versions == ["1.1.0"]


@pytest.mark.asyncio
async def test_missing_fixed_version_and_range_fails_closed():
    packages = {"app": {"1.1.0": release(["vuln>=2"])}, "vuln": VULN}
    assert (await resolve(packages, fixed=None)).action == "manual_remediation"
    assert (await resolve(packages, fixed="not-a-version")).action == "manual_remediation"


@pytest.mark.asyncio
async def test_vulnerable_range_takes_precedence():
    packages = {"app": {"1.1.0": release(["vuln==1.0"]), "1.2.0": release(["vuln>=2"])}, "vuln": VULN}
    assert (await resolve(packages, rng="<2.0.0")).qualifying_upgrade_versions == ["1.2.0"]


@pytest.mark.asyncio
async def test_transient_errors_retry_then_raise_metadata_error():
    attempts = 0

    def handler(request):
        nonlocal attempts
        attempts += 1
        return httpx.Response(429 if attempts == 1 else 200, json={"releases": {}})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        assert await PyPiMetadataClient(client, retry_delay=0).list_versions_descending("x") == []
    assert attempts == 2
