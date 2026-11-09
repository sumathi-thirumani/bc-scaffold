import httpx
import pytest

from src.engines.resolvers.recommendation_resolver.dotnet_recommendation_resolver import (
    NuGetRegistryClient,
    NuGetResolutionError,
    parse_nuget_range,
)
from src.engines.resolvers.recommendation_resolver_factory import NuGetParentVersionResolver


def leaf(version, deps=None, **extra):
    groups = [{"targetFramework": "net8.0", "dependencies": [
        {"id": name, "range": rng} for name, rng in (deps or {}).items()
    ]}]
    return {"catalogEntry": {"version": version, "dependencyGroups": groups, **extra}}


def registry(packages, status=None, paged=()):
    status = status or {}

    def handler(request):
        parts = request.url.path.strip("/").split("/")
        name = parts[-2]
        if parts[-1].startswith("page"):
            return httpx.Response(200, json={"items": packages[name]})
        if name in status:
            return httpx.Response(status[name])
        if name in paged:
            return httpx.Response(200, json={"items": [
                {"@id": f"https://api.nuget.org/v3/registration5-gz-semver2/{name}/page1"}
            ]})
        return httpx.Response(200, json={"items": [{"items": packages[name]}]})

    return httpx.MockTransport(handler)


async def select(packages, *, status=None, paged=(), paths=None, current="1.0.0", range_="<2.0.0"):
    async with httpx.AsyncClient(transport=registry(packages, status, paged)) as client:
        metadata = NuGetRegistryClient(client, retry_delay=0)
        resolver = NuGetParentVersionResolver(metadata=metadata)
        return await resolver.resolve(
            "App.Lib", "Vuln", "2.0.0", current,
            vulnerable_range=range_, dependency_paths=paths,
        )


VULN = [leaf("1.0.0"), leaf("2.0.0")]


@pytest.mark.parametrize("text,expected", [
    ("1.0", True), ("[1.0]", True), ("[1.0,2.0)", True), ("(1.0,)", True), ("(,2.0]", True),
    ("1.*", False), ("[1.0-beta,)", False), ("", False), ("(,)", False), ("(1.0)", False),
])
def test_range_parsing(text, expected):
    assert (parse_nuget_range(text) is not None) is expected


@pytest.mark.asyncio
async def test_lists_ascending_same_major_safe_candidates():
    packages = {
        "app.lib": [leaf("1.0.0", {"Vuln": "1.0.0"}), leaf("1.1.0", {"Vuln": "1.0.0"}),
                    leaf("1.2.0", {"Vuln": "2.0.0"}), leaf("1.3.0", {"Vuln": "[2.0.0,)"}),
                    leaf("2.0.0", {"Vuln": "2.0.0"})],
        "vuln": VULN,
    }
    result = await select(packages)
    assert result.qualifying_upgrade_versions == ["1.2.0", "1.3.0"]
    assert result.candidate_version == "1.2.0"
    assert result.requires_verification


@pytest.mark.asyncio
async def test_transitive_path_resolves_lowest_matching_version():
    packages = {
        "app.lib": [leaf("1.1.0", {"Mid": "1.0.0"}), leaf("1.2.0", {"Mid": "1.1.0"})],
        "mid": [leaf("1.0.0", {"Vuln": "1.0.0"}), leaf("1.1.0", {"Vuln": "2.0.0"})],
        "vuln": VULN,
    }
    paths = [[{"package": "App.Lib"}, {"package": "Mid"}, {"package": "Vuln"}]]
    assert (await select(packages, paths=paths)).qualifying_upgrade_versions == ["1.2.0"]


@pytest.mark.asyncio
async def test_dropping_the_dependency_counts_as_safe():
    packages = {"app.lib": [leaf("1.1.0")], "vuln": VULN}
    assert (await select(packages)).qualifying_upgrade_versions == ["1.1.0"]


@pytest.mark.asyncio
async def test_unsupported_range_and_unlisted_releases_fail_closed():
    packages = {
        "app.lib": [leaf("1.1.0", {"Vuln": "2.*"}), leaf("1.2.0", {"Vuln": "2.0.0"}, listed=False),
                    leaf("1.3.0", {"Vuln": "2.0.0"}, deprecation={"reasons": ["Legacy"]})],
        "vuln": VULN,
    }
    assert (await select(packages)).action == "manual_remediation"


@pytest.mark.asyncio
async def test_mismatched_path_endpoints_fail_closed():
    packages = {"app.lib": [leaf("1.1.0", {"Vuln": "2.0.0"})], "vuln": VULN}
    paths = [[{"package": "Other"}, {"package": "Vuln"}]]
    assert (await select(packages, paths=paths)).action == "manual_remediation"


@pytest.mark.asyncio
async def test_fetch_failure_is_not_reported_as_no_safe_release():
    result = await select({"app.lib": [], "vuln": VULN}, status={"app.lib": 503})
    assert result.action == "metadata_unavailable"
    assert result.candidate_version is None


@pytest.mark.asyncio
async def test_registration_pages_are_followed():
    packages = {"app.lib": [leaf("1.1.0", {"Vuln": "2.0.0"})], "vuln": VULN}
    result = await select(packages, paged={"app.lib"})
    assert result.qualifying_upgrade_versions == ["1.1.0"]


@pytest.mark.asyncio
async def test_transient_errors_retry_then_raise():
    attempts = 0

    def handler(request):
        nonlocal attempts
        attempts += 1
        return httpx.Response(429 if attempts == 1 else 200, json={"items": [{"items": [leaf("1.0.0")]}]})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        assert len(await NuGetRegistryClient(client, retry_delay=0).get("a")) == 1
    assert attempts == 2

    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(503))) as client:
        with pytest.raises(NuGetResolutionError):
            await NuGetRegistryClient(client, retry_delay=0).get("b")
