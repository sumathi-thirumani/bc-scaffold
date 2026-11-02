"""Factory for ecosystem-specific package upgrade recommendation resolvers."""

import asyncio
from typing import TypeAlias

from ...models.security_remediation_context import SecurityRemediationCache
from ...tools.ecosystem_manifest_tool import ManifestTool
from .recommendation_resolver.pip_recommendation_resolver import (
    PipParentVersionResolver,
)
from .recommendation_resolver.npm_recommendation_resolver import (
    NpmParentVersionResolver,
)

RecommendationResolver: TypeAlias = (
    NpmParentVersionResolver | PipParentVersionResolver
)


class RecommendationResolverFactory:
    """Create a parent-upgrade recommendation resolver for an ecosystem."""

    def __init__(
        self,
        cache: SecurityRemediationCache | None = None,
        manifest_tool: ManifestTool | None = None,
    ) -> None:
        self.manifest_tool = manifest_tool or ManifestTool(cache=cache)

    def create(
        self,
        ecosystem: str,
        *,
        package_text: str | None = None,
        lock_text: str | None = None,
    ) -> RecommendationResolver:
        normalized_ecosystem = ecosystem.lower()
        if normalized_ecosystem in {"npm", "npm_and_yarn"}:
            if package_text is None or lock_text is None:
                raise ValueError(
                    "package_text and lock_text are required for the npm ecosystem"
                )
            return NpmParentVersionResolver(package_text, lock_text)
        if normalized_ecosystem in {"pip", "pypi", "poetry"}:
            return PipParentVersionResolver()
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
        """Load repository manifests and create the ecosystem version resolver."""
        normalized_ecosystem = ecosystem.lower()
        if normalized_ecosystem in {"pip", "pypi", "poetry"}:
            return self.create(normalized_ecosystem)
        if normalized_ecosystem not in {"npm", "npm_and_yarn"}:
            return self.create(normalized_ecosystem)

        package_path, lock_path = ManifestTool.npm_recommendation_paths(manifest_path)

        package_text, lock_text = await asyncio.gather(
            self.manifest_tool.get(owner, repo, package_path, ref),
            self.manifest_tool.get(owner, repo, lock_path, ref),
        )
        if not package_text or not lock_text:
            raise ValueError(
                f"Cannot load npm recommendation resolver from {package_path} and {lock_path}"
            )
        return self.create(
            normalized_ecosystem,
            package_text=package_text,
            lock_text=lock_text,
        )
