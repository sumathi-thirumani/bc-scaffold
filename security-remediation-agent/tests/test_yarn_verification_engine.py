import asyncio
import json
from unittest.mock import AsyncMock

import pytest

from src.agents.remediation_planner_agent import RemediationPlannerAgent
from src.engines.grouping import UpgradeTargetBuilder
from src.agents.remediation_verification_agent import RemediationVerificationAgent
from src.engines.remediation_verification import yarn_verification_engine as yarn
from src.engines.remediation_verification.verification_engine import ManifestFile
from src.engines.remediation_verification.verification_engine_factory import VerificationEngineFactory
from src.models.security_package_triage import PackageUpgradeRecommendation, SecurityPackageTriage


def recommendation():
    return PackageUpgradeRecommendation(package="@scope/parent", from_version="1.0.0",
                                        qualifying_upgrade_versions=["1.1.0"], requires_verification=True)


def manifest(**changes):
    data = {"packageManager": "yarn@1.22.22", "dependencies": {"@scope/parent": "^1.0.0"}}
    data.update(changes)
    return ManifestFile("web/package.json", json.dumps(data), "web/yarn.lock", "# yarn lockfile v1\n")


@pytest.mark.parametrize("ecosystem", ["npm", "npm_and_yarn", "yarn"])
def test_factory_routes_yarn_and_checks_installed_exact_scoped_pin(monkeypatch, ecosystem):
    calls = []
    def install(args, cwd, env):
        calls.append(args)
        data = json.loads((cwd / "package.json").read_text())
        assert data["dependencies"]["@scope/parent"] == "1.1.0"
        installed = cwd / "node_modules/@scope/parent/package.json"
        installed.parent.mkdir(parents=True)
        installed.write_text(json.dumps({"name": "@scope/parent", "version": "1.1.0"}))
    monkeypatch.setattr(yarn, "run", install)
    original = manifest()
    rec = recommendation()
    assert VerificationEngineFactory().verify(ecosystem, original, [rec]) == [["1.1.0"]]
    assert "--ignore-scripts" in calls[0]
    assert "--production=false" in calls[0]
    assert calls[0][:3] == ["npx", "--yes", "yarn@1.22.22"]
    assert json.loads(original.content)["dependencies"]["@scope/parent"] == "^1.0.0"
    assert rec.qualifying_upgrade_versions[0].isVerified
    assert "peer dependency warnings" in original.verification_note


def test_successful_exit_with_wrong_version_is_not_verified(monkeypatch):
    def install(args, cwd, env):
        installed = cwd / "node_modules/@scope/parent/package.json"
        installed.parent.mkdir(parents=True)
        installed.write_text(json.dumps({"name": "@scope/parent", "version": "1.0.0"}))
    monkeypatch.setattr(yarn, "run", install)
    rec = recommendation()
    assert VerificationEngineFactory().verify("npm", manifest(), [rec]) == [[]]
    assert not rec.qualifying_upgrade_versions[0].isVerified
    assert "did not resolve" in rec.qualifying_upgrade_versions[0].verification_message


@pytest.mark.parametrize("changes", [
    {"packageManager": "yarn@4.1.1"}, {"workspaces": ["packages/*"]},
    {"installConfig": {"pnp": True}},
    {"dependencies": {"@scope/parent": "file:../parent"}},
])
def test_unsupported_layouts_never_install_and_display_not_verified(monkeypatch, changes):
    monkeypatch.setattr(yarn, "run", lambda *args: pytest.fail("Unsupported inputs must not install"))
    rec = recommendation()
    assert VerificationEngineFactory().verify("npm", manifest(**changes), [rec]) == [[]]
    finding = SecurityPackageTriage(package="child", ecosystem="npm", istransitive=True,
        manifest_path="web/yarn.lock", vulnerablility_version_range="", vulnerablility_fixed_version="",
        package_upgrade_recommendations=[rec])
    [target] = UpgradeTargetBuilder.build([finding])
    assert target["verification_status"] == "NOT VERIFIED"


def test_agent_uses_yarn_lock_and_rejects_omitted_root_config():
    files = {"web/package.json": manifest().content, "web/yarn.lock": "# yarn lockfile v1\n",
             ".yarnrc": 'registry "https://registry.example"'}
    tool = AsyncMock()
    tool.get.side_effect = lambda owner, repo, path, ref: files.get(path)
    result = asyncio.run(RemediationVerificationAgent(manifest_tool=tool)._manifest_file(
        "owner", "repo", "main", "npm", "web/package.json"))
    assert result.lock_path == "web/yarn.lock"
    assert "richer snapshot" in result.unsupported_reason


def test_agent_rejects_ancestor_workspace():
    files = {"web/package.json": manifest().content, "web/yarn.lock": "# yarn lockfile v1\n",
             "package.json": json.dumps({"workspaces": ["web"]})}
    tool = AsyncMock()
    tool.get.side_effect = lambda owner, repo, path, ref: files.get(path)
    result = asyncio.run(RemediationVerificationAgent(manifest_tool=tool)._manifest_file(
        "owner", "repo", "main", "npm", "web/yarn.lock"))
    assert "workspace" in result.unsupported_reason


@pytest.mark.parametrize("lock", [None, "__metadata:\n  version: 8\n"])
def test_missing_or_berry_lock_is_unsupported(monkeypatch, lock):
    monkeypatch.setattr(yarn, "run", lambda *args: pytest.fail("Must not install"))
    original = manifest()
    original.lock_content = lock
    rec = recommendation()
    assert VerificationEngineFactory().verify("npm", original, [rec]) == [[]]
    assert rec.qualifying_upgrade_versions[0].verification_message.startswith("Verification unsupported:")
