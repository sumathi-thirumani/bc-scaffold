"""Factory for ecosystem-specific package upgrade recommendation resolvers."""

from dataclasses import dataclass, field
from typing import TypeAlias

from ...models.security_remediation_cache import SecurityRemediationCache
from ...tools.ecosystem_manifest_tool import ManifestTool
from .recommendation_resolver.dotnet_recommendation_resolver import (
    NuGetRegistryClient,
    NuGetResolutionError,
)
from .recommendation_resolver.npm_recommendation_resolver import (
    NpmMetadataClient,
    NpmParentVersionResolver,
)
from .recommendation_resolver.pip_recommendation_resolver import (
    PipParentVersionResolver,
    PyPiMetadataClient,
)


@dataclass
class NuGetParentResolution:
    """Carry inferred NuGet parent candidates and an explanation when none qualify."""
    candidate_version: str | None
    qualifying_upgrade_versions: list[str] = field(default_factory=list)
    source: str = "nuget_registry_inferred"
    requires_verification: bool = True
    action: str = "upgrade_parent"
    reason: str = ""

    @property
    def resolved_version(self) -> str | None:
        return self.candidate_version

    @property
    def resolved(self) -> bool:
        return self.candidate_version is not None


class NuGetParentVersionResolver:
    """Shortlist parent versions whose registry dependencies avoid the vulnerable child.

    Core idea: follow the recorded parent-to-child paths through registry metadata
    and keep releases whose dependency constraints avoid the affected child.
    These candidates remain inferred; the verification engine later checks restore.
    """

    def __init__(
        self,
        *,
        metadata: NuGetRegistryClient | None = None,
    ) -> None:
        self.metadata = metadata or NuGetRegistryClient()

    async def resolve(
        self,
        parent: str,
        child: str,
        safe_child_version: str | None,
        current_parent_version: str | None = None,
        *,
        vulnerable_range: str | None = None,
        dependency_paths: list[list[dict[str, str]]] | None = None,
    ) -> NuGetParentResolution:
        try:
            candidates = await self.metadata.select_candidates(
                parent,
                child,
                vulnerable_range,
                safe_child_version,
                current_parent_version,
                dependency_paths=dependency_paths,
            )
        except NuGetResolutionError as exc:
            return NuGetParentResolution(
                candidate_version=None,
                action="metadata_unavailable",
                reason=f"Registry metadata could not be loaded: {exc}",
            )
        if not candidates:
            return NuGetParentResolution(
                candidate_version=None,
                action="manual_remediation",
                reason="No newer same-major parent release with a safe registry dependency graph was found",
            )
        return NuGetParentResolution(
            candidate_version=candidates[0],
            qualifying_upgrade_versions=candidates,
            reason="Registry dependency ranges avoid the affected child versions; outcome is unverified",
        )

RecommendationResolver: TypeAlias = (
    NpmParentVersionResolver | PipParentVersionResolver | NuGetParentVersionResolver
)


class RecommendationResolverFactory:
    """Create a parent-upgrade recommendation resolver for an ecosystem."""

    def __init__(
        self,
        cache: SecurityRemediationCache | None = None,
        manifest_tool: ManifestTool | None = None,
    ) -> None:
        self.manifest_tool = manifest_tool or ManifestTool(cache=cache)
        self.begin_run()

    def begin_run(self) -> None:
        """Start fresh npm and NuGet metadata caches shared by this run's resolvers."""
        self.npm_metadata = NpmMetadataClient()
        self.nuget_metadata = NuGetRegistryClient()
        self.pypi_metadata = PyPiMetadataClient()

    def create(
        self,
        ecosystem: str,
    ) -> RecommendationResolver:
        normalized_ecosystem = ecosystem.lower()
        if normalized_ecosystem in {"npm", "npm_and_yarn"}:
            return NpmParentVersionResolver(metadata=self.npm_metadata)
        if normalized_ecosystem in {"pip", "pypi", "poetry"}:
            return PipParentVersionResolver(pypi=self.pypi_metadata)
        if normalized_ecosystem == "nuget":
            return NuGetParentVersionResolver(metadata=self.nuget_metadata)
        raise ValueError(f"Unsupported recommendation resolver ecosystem: {ecosystem}")

    async def load(
        self,
        ecosystem: str,
        owner: str,
        repo: str,
        manifest_path: str,
        *,
        ref: str | None = None,
    ) -> RecommendationResolver:
        """Adapt the repository-aware caller interface to registry-only resolvers."""
        return self.create(ecosystem)
