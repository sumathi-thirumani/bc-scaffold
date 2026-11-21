import asyncio
from unittest.mock import AsyncMock
from src.agents.remediation_artifact_agent import RemediationArtifactAgent
from src.agents.remediation_planner_agent import RemediationPlannerAgent
from src.engines.grouping import UpgradeTargetBuilder
from src.engines.remediation_verification.verification_engine import ManifestFile, VerificationEngine
from src.models.plan_export import export_plan
from src.models.remediation_plan import RemediationPlan, RemeditionPackageBundle
from src.models.security_package_triage import PackageUpgradeRecommendation, SecurityPackageTriage


def test_prerelease_current_version_does_not_abort_project_review():
    from src.engines.resolvers.recommendation_resolver.dotnet_recommendation_resolver import DotNetRecommendationResolver
    tool = AsyncMock()
    project = '<Project><ItemGroup><PackageReference Include="Preview" Version="1.28.0-preview"/><PackageReference Include="Stable" Version="2.0.0"/></ItemGroup></Project>'
    tool.get.side_effect = lambda owner, repo, path, ref: project if path == "app.csproj" else None
    result = asyncio.run(DotNetRecommendationResolver(manifest_tool=tool)._declared_versions("o", "r", "app.csproj", "main"))
    assert result == {"preview": "1.28.0-preview", "stable": "2.0.0"}


def test_prerelease_fallback_flows_through_verification_and_rules_automatically():
    rec = PackageUpgradeRecommendation(package="Parent", from_version="1.0.0-alpha",
        qualifying_upgrade_versions=["1.1.0-beta"], allow_prerelease=True, requires_verification=True)
    assert rec.highest_stable_version == ""
    assert not PackageUpgradeRecommendation(package="Parent", from_version="1.0.0",
        qualifying_upgrade_versions=["1.1.0-beta"]).qualifying_upgrade_versions
    class Resolver(VerificationEngine):
        normalize_name = staticmethod(str.casefold)
        def run_resolver(self, snapshot, project, targets):
            assert next(iter(targets.values())) == {"parent": "1.1.0-beta"}
    assert Resolver().verify(ManifestFile("project.csproj", "<Project/>"), [rec]) == [["1.1.0-beta"]]
    triage = SecurityPackageTriage(package="Child", ecosystem="nuget", istransitive=True,
        manifest_path="project.csproj", vulnerablility_version_range="<2", vulnerablility_fixed_version="2",
        package_upgrade_recommendations=[rec], verified_versions={"Parent": "1.1.0-beta"})
    plan = RemediationPlan([RemeditionPackageBundle("nuget", "group", "high", [triage])])
    [target] = UpgradeTargetBuilder.build([triage])
    assert target["prerelease_fallback"]
    assert target["compatible_version"] == "1.1.0-beta"
    assert target["verification_status"] == "SUCCESS"
    assert export_plan(plan).bundles[0].packages[0].recommendations[0].prerelease_fallback
    [rule] = RemediationArtifactAgent._remediation_package_rules(plan)
    assert rule["ignoreUnstable"] is False
    assert "beta" in rule["allowedVersions"]
