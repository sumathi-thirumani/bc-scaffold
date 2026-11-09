import pytest
from types import SimpleNamespace
from src.engines.package_recommendation_resolver import PackageRecommendationResolver
from src.engines.resolvers.recommendation_resolver_factory import (
    NuGetParentResolution,
    NuGetParentVersionResolver,
)
from src.models.security_package_triage import SecurityPackageTriage, TransistiveSourcePackage


class _Resolver(NuGetParentVersionResolver):
    def __init__(self, resolution):
        self._resolution = resolution

    async def resolve(self, *args, **kwargs):
        return self._resolution


def _triage():
    return SecurityPackageTriage(
        package="Vuln", vulnerablility_version_range="<2.0.0",
        vulnerablility_fixed_version="2.0.0", ecosystem="nuget",
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("action", ["manual_remediation", "metadata_unavailable"])
async def test_unresolved_parent_yields_no_recommendation_but_records_action(action):
    introducer = TransistiveSourcePackage(package="App.Lib", version="1.0.0")
    resolution = NuGetParentResolution(candidate_version=None, action=action, reason="why")

    recommendation = await PackageRecommendationResolver._resolve_parent_recommendation(
        _triage(), "App.Lib", "1.0.0", _Resolver(resolution), introducer=introducer,
    )

    assert recommendation is None
    assert introducer.recommendation_action == action
    assert introducer.recommended_version is None


@pytest.mark.asyncio
async def test_direct_package_without_pr_uses_registry_versions_in_current_major():
    class Npm:
        async def get(self, package):
            return {"versions": {v: {} for v in ["0.28.1", "0.33.0", "0.34.0", "0.35.0", "1.20.0"]}}

    alerts = [SimpleNamespace(first_patched="0.34.0"), SimpleNamespace(first_patched="1.20.0")]
    triage = SecurityPackageTriage(
        package="axios", vulnerablility_version_range="<1.20.0", vulnerablility_fixed_version="1.20.0",
        current_version="0.28.1", ecosystem="npm", vulnerabilities=alerts,
    )
    resolver = PackageRecommendationResolver(SimpleNamespace(npm_metadata=Npm()))

    await resolver.populate_remediation_version(triage, {})

    [recommendation] = triage.package_upgrade_recommendations
    assert recommendation.requires_verification
    assert [c.version for c in recommendation.qualifying_upgrade_versions] == ["0.34.0", "0.35.0", "1.20.0"]
    assert triage.compatible_version("axios") == "0.34.0"


@pytest.mark.asyncio
async def test_direct_package_with_pr_is_widened_with_registry_versions():
    from src.models.security_package_triage import PackageUpgradeRecommendation

    class Npm:
        async def get(self, package):
            return {"versions": {v: {} for v in ["0.28.1", "0.34.0", "0.35.0", "1.20.0"]}}

    triage = SecurityPackageTriage(
        package="axios", vulnerablility_version_range="<1.20.0", vulnerablility_fixed_version="1.20.0",
        current_version="0.28.1", ecosystem="npm",
        vulnerabilities=[SimpleNamespace(first_patched="0.34.0"), SimpleNamespace(first_patched="1.20.0")],
        package_upgrade_recommendations=[PackageUpgradeRecommendation(
            package="axios", from_version="0.28.1", qualifying_upgrade_versions=["1.20.0"],
            source="dependabot_pr", pr_number=7)],
    )
    await PackageRecommendationResolver(SimpleNamespace(npm_metadata=Npm()))._populate_registry_recommendation(triage)

    [recommendation] = triage.package_upgrade_recommendations
    assert recommendation.pr_number == 7
    assert [c.version for c in recommendation.qualifying_upgrade_versions] == ["0.34.0", "0.35.0", "1.20.0"]
    assert triage.compatible_version("axios") == "0.34.0"


@pytest.mark.asyncio
async def test_resolved_parent_records_version_and_derives_compatible_version():
    introducer = TransistiveSourcePackage(package="App.Lib", version="1.0.0")
    resolution = NuGetParentResolution(
        candidate_version="1.2.0", qualifying_upgrade_versions=["1.2.0", "1.3.0"],
    )

    recommendation = await PackageRecommendationResolver._resolve_parent_recommendation(
        _triage(), "App.Lib", "1.0.0", _Resolver(resolution), introducer=introducer,
    )

    assert recommendation.default_compatible_version == "1.2.0"
    assert recommendation.requires_verification
    assert introducer.recommendation_action == "upgrade_parent"
    assert introducer.recommended_version == "1.2.0"
