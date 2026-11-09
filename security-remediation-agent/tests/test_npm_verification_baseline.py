import asyncio
import json
from types import SimpleNamespace as NS

import pytest

from src.agents.remediation_verification_agent import RemediationVerificationAgent
from src.models.security_package_triage import SecurityPackageTriage
from src.engines.remediation_verification import npm_verification_engine as npm
from src.engines.remediation_verification.verification_engine import ManifestFile
from src.engines.remediation_verification.verification_engine_factory import VerificationEngineFactory


def rec(name='example'):
    return NS(package=name, default_compatible_version='2.0.0',
              qualifying_upgrade_versions=[NS(version='2.0.0', isVerified=False,
                                             verification_status=None, verification_message=None)])


def triage_for(*recommendations):
    return SecurityPackageTriage(package='child', vulnerablility_version_range='', vulnerablility_fixed_version='',
                                 ecosystem='npm', manifest_path='web/package.json',
                                 package_upgrade_recommendations=list(recommendations))


@pytest.mark.parametrize('configured,strict_fails,expected', [
    (False, False, [False, False]),
    (False, True, [False, True, True]),
    (True, False, [True, True]),
])
def test_baseline_and_pins_share_peer_policy(monkeypatch, configured, strict_fails, expected):
    calls = []
    def resolve(args, cwd):
        legacy = '--legacy-peer-deps' in args
        data = json.loads((cwd / 'package.json').read_text())
        calls.append((legacy, data['dependencies']['example']))
        if strict_fails and not legacy:
            raise ValueError('ERESOLVE existing peer conflict')
        (cwd / 'package-lock.json').write_text(json.dumps({
            'lockfileVersion': 3, 'packages': {'node_modules/example': {'version': data['dependencies']['example']}}}))
    monkeypatch.setattr(npm, 'run', resolve)
    manifest = ManifestFile('web/package.json', '{"dependencies":{"example":"1.0.0"}}', legacy_peer_deps=configured)
    recommendation = rec()
    assert npm.NpmVerificationEngine().verify(manifest, [recommendation], ['2.0.0']) == [['2.0.0']]
    assert [legacy for legacy, _ in calls] == expected
    assert calls[0][1] == '1.0.0'
    assert calls[-1][1] == '2.0.0'
    assert bool(manifest.verification_note) == (configured or strict_fails)


def test_failed_baseline_skips_all_candidates(monkeypatch):
    calls = []
    def fail(args, cwd):
        calls.append(args)
        raise ValueError('ERESOLVE baseline broken')
    monkeypatch.setattr(npm, 'run', fail)
    manifest = ManifestFile('package.json', '{"dependencies":{"example":"1.0.0"}}')
    recommendations = [rec() for _ in range(98)]
    assert VerificationEngineFactory().verify('npm', manifest, recommendations) == [[]] * 98
    assert len(calls) == 2
    assert manifest.baseline_failed
    assert all(not r.qualifying_upgrade_versions[0].isVerified for r in recommendations)


def test_manifest_shared_across_bundles_has_one_failure_note(monkeypatch):
    calls = []
    class Factory:
        def verify(self, ecosystem, manifest, recommendations, compatible_versions):
            calls.append(len(recommendations))
            manifest.baseline_failed = True
            manifest.verification_note = 'Baseline resolution failed for web/package.json'
            return [[] for _ in recommendations]
    agent = RemediationVerificationAgent(manifest_tool=NS(), engine_factory=Factory())
    async def manifest(*args):
        return ManifestFile('web/package.json', '{}')
    monkeypatch.setattr(agent, '_manifest_file', manifest)
    triages = [triage_for(rec(name)) for name in ['a', 'b']]
    plan = NS(remediation_plan_bundles=[NS(packages=[t]) for t in triages])
    asyncio.run(agent.verify(plan, {'owner': 'o', 'name': 'r'}))
    assert calls == [2]
    assert sum('Baseline resolution failed' in t.notes for t in triages) == 1


def test_project_npmrc_overrides_root_setting():
    class Tool:
        async def get(self, owner, name, path, ref):
            return {'web/package.json': '{}', '.npmrc': 'legacy-peer-deps=false',
                    'web/.npmrc': 'legacy-peer-deps=true\n//registry/:_authToken=unused'}.get(path)
    manifest = asyncio.run(RemediationVerificationAgent(manifest_tool=Tool())._manifest_file('o', 'r', 'main', 'npm', 'web/package.json'))
    assert manifest.legacy_peer_deps is True
    assert 'unused' not in repr(manifest)


def test_non_peer_baseline_failure_does_not_retry_legacy(monkeypatch):
    calls = []
    def fail(args, cwd):
        calls.append(args)
        raise ValueError('registry unavailable')
    monkeypatch.setattr(npm, 'run', fail)
    manifest = ManifestFile('package.json', '{}')
    recommendation = rec()
    assert VerificationEngineFactory().verify('npm', manifest, [recommendation]) == [[]]
    assert len(calls) == 1
    assert 'see manifest note' in recommendation.qualifying_upgrade_versions[0].verification_message


def test_ecosystem_filter_keeps_code_scanning_and_selected_alerts():
    from src.models.security_findings import SecurityFindings
    from src.orchestrator.security_orchestrator import SecurityOrchestrator
    orchestrator = object.__new__(SecurityOrchestrator)
    orchestrator.ecosystems = frozenset({'npm'})
    selected, excluded, code = NS(ecosystem='NPM'), NS(ecosystem='pip'), object()
    findings = SecurityFindings([selected, excluded], [code])
    filtered = orchestrator._filter_ecosystems(findings)
    assert filtered.dependabot_alerts == [selected]
    assert filtered.codescanning_alerts == [code]
    assert findings.dependabot_alerts == [selected, excluded]
    orchestrator.ecosystems = None
    assert orchestrator._filter_ecosystems(findings) is findings
