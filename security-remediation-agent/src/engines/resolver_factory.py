"""Factories for ecosystem-specific relationship and recommendation resolvers."""

import asyncio
import json
from pathlib import PurePosixPath
from typing import TypeAlias

from ..models.security_remediation_context import SecurityRemediationCache
from ..utils.manifest_provider import ManifestProvider
from .recommendation_resolver.pip_parent_version_resolver import (
    PipParentVersionResolver,
)
from .relationship_resolver.npm_resolver import NpmResolver
from .relationship_resolver.pip_resolver import PipResolver
from .relationship_resolver.poetry_resolver import PoetryResolver
from .version_resolver.npm_parent_version_resolver import NpmParentVersionResolver

RelationshipResolver: TypeAlias = NpmResolver | PipResolver | PoetryResolver
RecommendationResolver: TypeAlias = (
    NpmParentVersionResolver | PipParentVersionResolver
)


class RelationshipResolverFactory:
    """Create a dependency relationship resolver for an ecosystem."""

    async def create(
        self,
        ecosystem: str,
        lock_text: str,
        *,
        project_text: str | None = None,
    ) -> RelationshipResolver:
        normalized_ecosystem = ecosystem.lower()
        if normalized_ecosystem in {"npm", "npm_and_yarn"}:
            return NpmResolver(json.loads(lock_text))
        if normalized_ecosystem in {"pip", "pypi"}:
            return await asyncio.to_thread(PipResolver.from_text, lock_text)
        if normalized_ecosystem == "poetry":
            if project_text is None:
                raise ValueError("project_text is required for the poetry ecosystem")
            return PoetryResolver(lock_text, project_text)
        raise ValueError(f"Unsupported relationship resolver ecosystem: {ecosystem}")


class RecommendationResolverFactory:
    """Create a parent-upgrade recommendation resolver for an ecosystem."""

    def __init__(
        self,
        cache: SecurityRemediationCache | None = None,
        manifest_provider: ManifestProvider | None = None,
    ) -> None:
        self.manifest_provider = manifest_provider or ManifestProvider(cache=cache)

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

        path = PurePosixPath(manifest_path)
        if path.name in {"package-lock.json", "npm-shrinkwrap.json"}:
            lock_path = str(path)
            package_path = str(path.parent / "package.json")
        else:
            package_path = str(path.parent / "package.json")
            lock_path = str(path.parent / "package-lock.json")

        package_text, lock_text = await asyncio.gather(
            self.manifest_provider.get(owner, repo, package_path, ref),
            self.manifest_provider.get(owner, repo, lock_path, ref),
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
