import pytest

from src.config.security_remediation_config import ConfigError, SecurityRemediationConfig, parse_ecosystems
from src.models.security_remediation_constants import SecurityRemediationConstants


def load(env, **kwargs):
    return SecurityRemediationConfig.load(env=env, **kwargs)


def test_actions_environment_drives_all_values():
    config = load({
        "GITHUB_TOKEN": "ghp_secret123", "GITHUB_REPOSITORY": "sumathi-thirumani/unified-scheduling",
        "SECURITY_REMEDIATION_ECOSYSTEMS": "npm, PIP", "SECURITY_REMEDIATION_VERIFICATION_ENABLED": "false",
    })
    assert config.repository == {"owner": "sumathi-thirumani", "name": "unified-scheduling"}
    assert config.ecosystems == frozenset({"npm", "npm_and_yarn", "yarn", "pip"})
    assert config.verification_enabled is False
    assert "ghp_secret123" not in repr(config)


def test_arguments_override_environment_and_accept_urls():
    config = load({"GITHUB_TOKEN": "t", "GITHUB_REPOSITORY": "a/b"}, owner="o",
                  repo="https://github.com/o/r.git", ecosystems="nuget")
    assert (config.owner, config.repo) == ("o", "r")
    assert config.ecosystems == frozenset({"nuget"})


def test_defaults_are_all_ecosystems_with_verification():
    config = load({"GITHUB_TOKEN": "t"}, owner="o", repo="r")
    assert config.ecosystems == SecurityRemediationConstants.SUPPORTED_ECOSYSTEMS
    assert config.verification_enabled is True


@pytest.mark.parametrize("env,kwargs", [
    ({}, {"owner": "o", "repo": "r"}),
    ({"GITHUB_TOKEN": "t"}, {}),
    ({"GITHUB_TOKEN": "t", "SECURITY_REMEDIATION_VERIFICATION_ENABLED": "maybe"}, {"owner": "o", "repo": "r"}),
])
def test_invalid_configuration_raises(env, kwargs):
    with pytest.raises(ConfigError):
        load(env, **kwargs)


def test_all_and_unknown_ecosystems_proceed(caplog):
    assert parse_ecosystems("python") == {"pip", "pypi", "poetry"}
    assert parse_ecosystems("npm/yarn/pnpm") == {"npm", "npm_and_yarn", "yarn"}
    assert parse_ecosystems("dotnet,npm") == {"nuget", "npm", "npm_and_yarn", "yarn"}
    base = {"GITHUB_TOKEN": "t"}
    supported = SecurityRemediationConstants.SUPPORTED_ECOSYSTEMS
    assert load(base, owner="o", repo="r", ecosystems="All").ecosystems == supported
    with caplog.at_level("WARNING"):
        mixed = load(base, owner="o", repo="r", ecosystems="npm,cobol")
        only_unknown = load(base, owner="o", repo="r", ecosystems="cobol")
    assert mixed.ecosystems == frozenset({"npm", "npm_and_yarn", "yarn"})
    assert only_unknown.ecosystems == supported
    assert "'cobol' was not found" in caplog.text



def test_ref_argument_overrides_environment():
    config = load({'GITHUB_TOKEN': 't', 'SECURITY_REMEDIATION_REF': 'develop'},
                  owner='o', repo='r', ref='release')
    assert config.repository['ref'] == 'release'
    assert load({'GITHUB_TOKEN': 't', 'SECURITY_REMEDIATION_REF': 'develop'}, owner='o', repo='r').ref == 'develop'
