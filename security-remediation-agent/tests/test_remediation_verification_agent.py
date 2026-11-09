import asyncio
from types import SimpleNamespace as NS
from unittest.mock import AsyncMock

from src.agents.remediation_verification_agent import RemediationVerificationAgent
from src.engines.remediation_verification.verification_engine import ManifestFile
from src.models.remediation_plan import RemediationPlan, RemeditionPackageBundle
from src.models.security_package_triage import PackageUpgradeRecommendation, SecurityPackageTriage


def test_agent_populates_versions_and_keeps_failures_unresolved():
    recs = [PackageUpgradeRecommendation(package=name, from_version="1.0.0",
             qualifying_upgrade_versions=["2.0.0"]) for name in ("a", "b")]
    triage = SecurityPackageTriage(package="child", ecosystem="npm", manifest_path="package.json",
        vulnerablility_version_range="<2", vulnerablility_fixed_version="2",
        package_upgrade_recommendations=recs, verified_versions={"a": "stale", "b": "stale"},
            compatible_versions={"a": "2.0.0", "b": "2.0.0"})
    plan = RemediationPlan([RemeditionPackageBundle("npm", "default", "high", [triage])])
    class Factory:
        def verify(self, ecosystem, manifest, recommendations, compatible_versions):
            assert compatible_versions == ["2.0.0", "2.0.0"]
            return [["2.0.0"], []]
    agent = RemediationVerificationAgent(manifest_tool=NS(), engine_factory=Factory())
    agent._manifest_file = AsyncMock(return_value=ManifestFile("package.json", "{}"))
    assert asyncio.run(agent.verify(plan, {"owner": "o", "name": "r"}, ref="feature")) is plan
    assert triage.verified_versions == {"a": "2.0.0", "b": None}
    assert "Verification failed for b" in triage.notes
    assert agent._manifest_file.await_args.args[2] == "feature"


def test_missing_manifest_clears_previous_verification():
    rec = PackageUpgradeRecommendation(package="a", from_version="1", qualifying_upgrade_versions=["2"])
    triage = SecurityPackageTriage(package="a", ecosystem="npm", manifest_path="package.json",
        vulnerablility_version_range="", vulnerablility_fixed_version="",
        package_upgrade_recommendations=[rec], verified_versions={"a": "stale"})
    plan = NS(remediation_plan_bundles=[NS(packages=[triage])])
    agent = RemediationVerificationAgent(manifest_tool=NS())
    agent._manifest_file = AsyncMock(return_value=None)
    asyncio.run(agent.verify(plan, {"owner": "o", "name": "r"}))
    assert triage.verified_version("a") is None
    assert rec.qualifying_upgrade_versions[0].verification_status == "FAILED"



def test_timeout_worker_cannot_mutate_published_candidates(monkeypatch):
    import threading
    from src.agents import remediation_verification_agent as module
    ready, release = threading.Event(), threading.Event()
    class SlowFactory:
        def verify(self, ecosystem, manifest, recommendations, compatible_versions):
            ready.set()
            release.wait(2)
            recommendations[0].qualifying_upgrade_versions[0].isVerified = True
            return [['2']]
    rec = PackageUpgradeRecommendation(package='a', from_version='1', qualifying_upgrade_versions=['2'])
    triage = SecurityPackageTriage(package='a', ecosystem='npm', manifest_path='package.json',
        vulnerablility_version_range='', vulnerablility_fixed_version='', package_upgrade_recommendations=[rec])
    plan = NS(remediation_plan_bundles=[NS(packages=[triage])])
    agent = RemediationVerificationAgent(manifest_tool=NS(), engine_factory=SlowFactory())
    agent._manifest_file = AsyncMock(return_value=ManifestFile('package.json', '{}'))
    monkeypatch.setattr(module, 'VERIFICATION_TIMEOUT_SECONDS', 0.05)
    async def check():
        await agent.verify(plan, {'owner': 'o', 'name': 'r'})
        release.set()
    try:
        asyncio.run(check())
    finally:
        release.set()
    assert ready.is_set()
    assert triage.verified_version('a') is None
    assert not rec.qualifying_upgrade_versions[0].isVerified
    assert rec.qualifying_upgrade_versions[0].verification_status == 'FAILED'
