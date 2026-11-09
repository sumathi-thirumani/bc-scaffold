import httpx
import pytest

from src.engines.resolvers.recommendation_resolver.npm_recommendation_resolver import (
    NpmMetadataClient,
    NpmParentVersionResolver,
)


def registry(packages, status=None):
    status = status or {}

    def handler(request):
        name = request.url.path.lstrip("/").replace("%40", "@").replace("%2F", "/")
        if name in status:
            return httpx.Response(status[name])
        return httpx.Response(200, json={"versions": packages[name]})

    return httpx.MockTransport(handler)


async def resolve(packages, *, status=None, node_version=None, **kwargs):
    async with httpx.AsyncClient(transport=registry(packages, status)) as client:
        resolver = NpmParentVersionResolver(
            metadata=NpmMetadataClient(client, retry_delay=0), node_version=node_version,
        )
        return await resolver.resolve(
            kwargs.pop("parent", "app"), kwargs.pop("child", "vuln"), "<2.0.0",
            current_parent_version="1.0.0", **kwargs,
        )


VULN = {"1.0.0": {}, "2.0.0": {}}


@pytest.mark.asyncio
async def test_no_newer_parent_release_is_distinguished_from_rejected_candidates():
    result = await resolve({"app": {"1.0.0": {"dependencies": {"vuln": "^1.0.0"}}}, "vuln": VULN})
    assert result.action == "manual_remediation"
    assert "No newer eligible stable parent release exists" in result.reason
    assert "current=1.0.0, latest eligible=1.0.0" in result.reason
    assert "separate validation" in result.reason

    result = await resolve({"app": {"1.1.0": {"dependencies": {"vuln": "^1.0.0"}}}, "vuln": VULN})
    assert "No newer eligible stable parent release exists" not in result.reason


@pytest.mark.asyncio
async def test_missing_parent_upgrade_reason_is_saved_without_duplicate_notes():
    from dataclasses import asdict
    from unittest.mock import AsyncMock
    from src.engines.package_recommendation_resolver import PackageRecommendationResolver
    from src.engines.resolvers.recommendation_resolver.npm_recommendation_resolver import NpmParentResolution
    from src.models.security_package_triage import SecurityPackageTriage

    triage = SecurityPackageTriage(
        package="minimatch", ecosystem="npm", manifest_path="web/package-lock.json",
        vulnerablility_version_range="<11.0.1", vulnerablility_fixed_version="11.0.1",
        notes="Existing finding note",
    )
    resolver = NpmParentVersionResolver()
    resolver.resolve = AsyncMock(return_value=NpmParentResolution(
        parent="eslint", child="minimatch", action="manual_remediation",
        reason="No newer eligible stable parent release exists",
    ))
    for parent in ["eslint", "eslint", "@vue/test-utils"]:
        assert await PackageRecommendationResolver._resolve_parent_recommendation(
            triage, parent, "1.0.0", resolver,
        ) is None
    lines = asdict(triage)["notes"].splitlines()
    assert len(lines) == 3
    assert lines[0] == "Existing finding note"
    assert lines[1].startswith("eslint 1.0.0 (manual_remediation):")
    assert lines[2].startswith("@vue/test-utils 1.0.0 (manual_remediation):")


@pytest.mark.asyncio
async def test_picks_first_safe_parent_release():
    packages = {
        "app": {"1.0.0": {"dependencies": {"vuln": "^1.0.0"}},
                "1.1.0": {"dependencies": {"vuln": "^1.0.0"}},
                "2.0.0": {"dependencies": {"vuln": "^2.0.0"}}},
        "vuln": VULN,
    }
    result = await resolve(packages)
    assert result.resolved_version == "2.0.0"


@pytest.mark.asyncio
async def test_fetch_failure_is_not_reported_as_no_safe_release():
    result = await resolve({"app": {}, "vuln": VULN}, status={"app": 503})
    assert not result.resolved
    assert result.action == "metadata_unavailable"


@pytest.mark.asyncio
async def test_missing_dependency_metadata_is_unverified():
    packages = {"app": {"2.0.0": {"dependencies": {"mid": "^1.0.0"}}}, "mid": {}}
    paths = [[{"package": "app"}, {"package": "mid"}, {"package": "vuln"}]]
    result = await resolve(packages, status={"mid": 404}, dependency_paths=paths)
    assert result.action == "metadata_unavailable"


@pytest.mark.asyncio
async def test_node_engine_filter_applies_only_when_configured():
    packages = {
        "app": {"2.0.0": {"dependencies": {"vuln": "^2.0.0"}, "engines": {"node": ">=20"}}},
        "vuln": VULN,
    }
    assert (await resolve(packages)).resolved_version == "2.0.0"
    assert (await resolve(packages, node_version="v18.0.0")).action == "manual_remediation"
    assert (await resolve(packages, node_version="20.1.0")).resolved_version == "2.0.0"


@pytest.mark.asyncio
async def test_cycle_and_diamond_graphs_terminate_safely():
    packages = {
        "app": {"2.0.0": {"dependencies": {"a": "^1.0.0", "b": "^1.0.0"}}},
        "a": {"1.0.0": {"dependencies": {"b": "^1.0.0", "vuln": "^2.0.0"}}},
        "b": {"1.0.0": {"dependencies": {"a": "^1.0.0", "vuln": "^2.0.0"}}},
        "vuln": VULN,
    }
    paths = [
        [{"package": "app"}, {"package": "a"}, {"package": "vuln"}],
        [{"package": "app"}, {"package": "b"}, {"package": "vuln"}],
        [{"package": "app"}, {"package": "a"}, {"package": "b"}, {"package": "vuln"}],
        [{"package": "app"}, {"package": "b"}, {"package": "a"}, {"package": "vuln"}],
    ]
    assert (await resolve(packages, dependency_paths=paths)).resolved_version == "2.0.0"


@pytest.mark.asyncio
async def test_unsafe_branch_in_diamond_rejects_release():
    packages = {
        "app": {"2.0.0": {"dependencies": {"a": "^1.0.0", "b": "^1.0.0"}}},
        "a": {"1.0.0": {"dependencies": {"vuln": "^2.0.0"}}},
        "b": {"1.0.0": {"dependencies": {"vuln": "^1.0.0"}}},
        "vuln": VULN,
    }
    paths = [
        [{"package": "app"}, {"package": "a"}, {"package": "vuln"}],
        [{"package": "app"}, {"package": "b"}, {"package": "vuln"}],
    ]
    assert (await resolve(packages, dependency_paths=paths)).action == "manual_remediation"


@pytest.mark.asyncio
async def test_mismatched_path_endpoints_fail_closed():
    packages = {"app": {"2.0.0": {"dependencies": {"vuln": "^2.0.0"}}}, "vuln": VULN}
    paths = [[{"package": "other"}, {"package": "vuln"}]]
    assert (await resolve(packages, dependency_paths=paths)).action == "manual_remediation"


@pytest.mark.asyncio
async def test_scoped_package_names_are_encoded():
    packages = {"@org/app": {"2.0.0": {"dependencies": {"vuln": "^2.0.0"}}}, "vuln": VULN}
    result = await resolve(packages, parent="@org/app")
    assert result.resolved_version == "2.0.0"


@pytest.mark.asyncio
async def test_unsupported_alias_spec_fails_closed():
    packages = {"app": {"2.0.0": {"dependencies": {"vuln": "npm:other@1"}}}, "vuln": VULN}
    assert (await resolve(packages)).action == "manual_remediation"
