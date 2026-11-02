"""Factory for ecosystem-specific dependency relationship resolvers."""

from typing import TypeAlias

from .resolvers.relationship_version_resolvers.npm_relationship_version_resolver import (
    NpmRelationshipVersionResolver,
)
from .resolvers.relationship_version_resolvers.pip_relationship_version_resolver import (
    PipRelationshipVersionResolver,
)
from .resolvers.relationship_version_resolvers.poetry_relationship_version_resolver import (
    PoetryRelationshipVersionResolver,
)
from .resolvers.relationship_version_resolvers.yarn_relationship_version_resolver import (
    YarnRelationshipVersionResolver,
)
RelationshipResolver: TypeAlias = (
    NpmRelationshipVersionResolver
    | PipRelationshipVersionResolver
    | PoetryRelationshipVersionResolver
    | YarnRelationshipVersionResolver
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
            if project_text is None:
                raise ValueError("project_text (package.json) is required for the npm ecosystem")
            return NpmRelationshipVersionResolver(lock_text, project_text)
        if normalized_ecosystem == "yarn":
            if project_text is None:
                raise ValueError("project_text (package.json) is required for the yarn ecosystem")
            return YarnRelationshipVersionResolver(lock_text, project_text)
        if normalized_ecosystem in {"pip", "pypi", "python"}:
            # Triage is offline: only pip-compile graphs, never a pip/PyPI resolution.
            return PipRelationshipVersionResolver.from_compiled_text(lock_text)
        if normalized_ecosystem == "poetry":
            if project_text is None:
                raise ValueError("project_text is required for the poetry ecosystem")
            return PoetryRelationshipVersionResolver(lock_text, project_text)
        raise ValueError(f"Unsupported relationship resolver ecosystem: {ecosystem}")
