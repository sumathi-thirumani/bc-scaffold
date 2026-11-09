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
    for rec in recs:
        rec.verified_version = "stale"
    triage = SecurityPackageTriage(package="child", ecosystem="npm", manifest_path="package.json",
        vulnerablility_version_range="<2", vulnerablility_fixed_version="2",
        package_upgrade_recommendations=recs)
    plan = RemediationPlan([RemeditionPackageBundle("npm", "default", "high", [triage])])
    class Factory:
        def verify(self, ecosystem, manifest, recommendations):
            return [["2.0.0"], []]
    agent = RemediationVerificationAgent(manifest_tool=NS(), engine_factory=Factory())
    agent._manifest_file = AsyncMock(return_value=ManifestFile("package.json", "{}"))
    assert asyncio.run(agent.verify(plan, {"owner": "o", "name": "r"}, ref="feature")) is plan
    assert [r.verified_version for r in recs] == ["2.0.0", None]
    assert "Verification failed for b" in triage.notes
    assert agent._manifest_file.await_args.args[2] == "feature"


def test_missing_manifest_clears_previous_verification():
    rec = PackageUpgradeRecommendation(package="a", from_version="1", qualifying_upgrade_versions=["2"])
    rec.verified_version = "stale"
    triage = NS(ecosystem="npm", manifest_path="package.json", notes="", package_upgrade_recommendations=[rec])
    plan = NS(remediation_plan_bundles=[NS(packages=[triage])])
    agent = RemediationVerificationAgent(manifest_tool=NS())
    agent._manifest_file = AsyncMock(return_value=None)
    asyncio.run(agent.verify(plan, {"owner": "o", "name": "r"}))
    assert rec.verified_version is None
    assert rec.qualifying_upgrade_versions[0].verification_status == "FAILED"



def test_timeout_worker_cannot_mutate_published_candidates(monkeypatch):
    import threading
    from src.agents import remediation_verification_agent as module
    ready, release = threading.Event(), threading.Event()
    class SlowFactory:
        def verify(self, ecosystem, manifest, recommendations):
            ready.set()
            release.wait(2)
            recommendations[0].qualifying_upgrade_versions[0].isVerified = True
            return [['2']]
    rec = PackageUpgradeRecommendation(package='a', from_version='1', qualifying_upgrade_versions=['2'])
    triage = NS(ecosystem='npm', manifest_path='package.json', notes='', package_upgrade_recommendations=[rec])
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
    assert rec.verified_version is None
    assert not rec.qualifying_upgrade_versions[0].isVerified
    assert rec.qualifying_upgrade_versions[0].verification_status == 'FAILED'
