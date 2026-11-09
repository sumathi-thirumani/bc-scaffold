"""Regression tests for verification evidence and combined fallback resolution."""
from types import SimpleNamespace as NS

from src.engines.remediation_verification.verification_engine import (
    ManifestFile, ResolutionConflict, VerificationEngine,
)


class Resolver(VerificationEngine):
    def __init__(self, resolve):
        self.resolve = resolve
        self.calls = []

    def normalize_name(self, name):
        return name.casefold()

    def run_resolver(self, root, project, targets):
        pins = next(iter(targets.values()))
        self.calls.append(dict(pins))
        self.resolve(pins)


def recommendation(name, minimum='2.0.0', compatible='3.0.0'):
    return NS(package=name, minimum_patched_version=minimum, compatible_version=compatible,
              qualifying_upgrade_versions=[NS(version=v, isVerified=False,
                  verification_status=None, verification_message=None)
                  for v in dict.fromkeys([minimum, compatible])])


def test_higher_compatible_version_cannot_bypass_resolver():
    def reject(pins):
        raise ResolutionConflict(pins, 'unresolvable')
    engine = Resolver(reject)
    rec = recommendation('a')
    assert engine.verify(ManifestFile('package.json', '{}'), [rec]) == [[]]
    assert engine.calls == [{'a': '2.0.0'}, {'a': '3.0.0'}]
    assert all(not c.isVerified and c.verification_status == 'FAILED'
               for c in rec.qualifying_upgrade_versions)


def test_fallback_is_verified_with_previously_accepted_pins():
    def resolve(pins):
        if pins.get('b') == '2.0.0':
            raise ResolutionConflict({'b'}, 'minimum rejected')
    engine = Resolver(resolve)
    recs = [recommendation('a'), recommendation('b')]
    assert engine.verify(ManifestFile('package.json', '{}'), recs) == [['2.0.0'], ['3.0.0']]
    assert engine.calls == [
        {'a': '2.0.0', 'b': '2.0.0'}, {'a': '2.0.0'}, {'a': '2.0.0', 'b': '3.0.0'}]
    assert recs[0].qualifying_upgrade_versions[0].isVerified
    assert recs[1].qualifying_upgrade_versions[1].isVerified


def test_fallback_conflicting_with_accepted_upgrade_is_rejected():
    def resolve(pins):
        if 'a' in pins and 'b' in pins:
            raise ResolutionConflict({'b'}, 'conflicts with a')
    engine = Resolver(resolve)
    recs = [recommendation('a'), recommendation('b')]
    assert engine.verify(ManifestFile('package.json', '{}'), recs) == [['2.0.0'], []]
    assert {'a': '2.0.0', 'b': '3.0.0'} in engine.calls
    assert all(not c.isVerified for c in recs[1].qualifying_upgrade_versions)


def test_accepted_version_is_cleared_if_combined_retry_rejects_it():
    def resolve(pins):
        if pins.get('b') == '2.0.0':
            raise ResolutionConflict({'b'}, 'minimum rejected')
        if 'a' in pins and pins.get('b') == '3.0.0':
            raise ResolutionConflict({'a'}, 'a conflicts with fallback')
    engine = Resolver(resolve)
    recs = [recommendation('a'), recommendation('b')]
    assert engine.verify(ManifestFile('package.json', '{}'), recs) == [[], ['3.0.0']]
    assert engine.calls[-1] == {'b': '3.0.0'}
    assert recs[0].qualifying_upgrade_versions[0].verification_status == 'FAILED'
    assert not recs[0].qualifying_upgrade_versions[0].isVerified


def test_successful_minimum_set_requires_no_fallback_run():
    engine = Resolver(lambda pins: None)
    recs = [recommendation('a'), recommendation('b')]
    assert engine.verify(ManifestFile('package.json', '{}'), recs) == [['2.0.0'], ['2.0.0']]
    assert len(engine.calls) == 1


def test_engine_populates_verified_version_from_final_fallback_set():
    def resolve(pins):
        if pins.get('b') == '2.0.0':
            raise ResolutionConflict({'b'}, 'minimum rejected')
        if 'a' in pins and pins.get('b') == '3.0.0':
            raise ResolutionConflict({'a'}, 'conflicts with fallback')
    recs = [recommendation('a'), recommendation('b')]
    for rec in recs:
        rec.verified_version = 'stale'
    Resolver(resolve).verify(ManifestFile('package.json', '{}'), recs)
    assert [rec.verified_version for rec in recs] == [None, '3.0.0']


def test_factory_failure_clears_previous_verified_version():
    from src.engines.remediation_verification.verification_engine_factory import VerificationEngineFactory
    rec = recommendation('a')
    rec.verified_version = 'stale'
    VerificationEngineFactory().verify('unsupported', ManifestFile('package.json', '{}'), [rec])
    assert rec.verified_version is None



def test_duplicate_recommendations_use_only_common_candidate():
    first = recommendation('shared', minimum='2.0.0', compatible='3.0.0')
    second = recommendation('SHARED', minimum='3.0.0', compatible='3.0.0')
    engine = Resolver(lambda pins: None)
    assert engine.verify(ManifestFile('package.json', '{}'), [first, second]) == [['3.0.0'], ['3.0.0']]
    assert engine.calls == [{'shared': '3.0.0'}]
    assert not first.qualifying_upgrade_versions[0].isVerified
    assert first.qualifying_upgrade_versions[1].isVerified
    assert first.verified_version == second.verified_version == '3.0.0'


def test_disjoint_duplicate_candidates_do_not_reach_resolver():
    first = recommendation('shared', minimum='2.0.0', compatible='2.0.0')
    second = recommendation('shared', minimum='3.0.0', compatible='3.0.0')
    engine = Resolver(lambda pins: None)
    assert engine.verify(ManifestFile('package.json', '{}'), [first, second]) == [[], []]
    assert not engine.calls
    assert all(r.qualifying_upgrade_versions[0].verification_status == 'FAILED' for r in (first, second))
