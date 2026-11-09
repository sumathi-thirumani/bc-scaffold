"""Factory for ecosystem-specific dependency relationship resolvers."""

from collections.abc import Mapping
from typing import TypeAlias

from .resolvers.relationship_version_resolvers.npm_relationship_version_resolver import (
    NpmRelationshipVersionResolver,
)
from .resolvers.relationship_version_resolvers.nuget_relationship_version_resolver import (
    NuGetRelationshipVersionResolver,
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
    | NuGetRelationshipVersionResolver
    | PipRelationshipVersionResolver
    | PoetryRelationshipVersionResolver
    | YarnRelationshipVersionResolver
)


class RelationshipResolverFactory:
    """Create a dependency relationship resolver for an ecosystem."""

    async def create(
        self,
        ecosystem: str,
        lock_text: str | None = None,
        *,
        project_text: str | None = None,
        project_files: Mapping[str, str] | None = None,
        support_files: Mapping[str, str] | None = None,
        requirements_path: str = "requirements.txt",
        source_path: str | None = None,
        source_text: str | None = None,
    ) -> RelationshipResolver:
        normalized_ecosystem = ecosystem.lower()
        if normalized_ecosystem in {"npm", "npm_and_yarn"}:
            if project_text is None:
                raise ValueError("project_text (package.json) is required for the npm ecosystem")
            if lock_text is None:
                raise ValueError("lock_text (package-lock.json) is required for the npm ecosystem")
            return NpmRelationshipVersionResolver(lock_text, project_text)
        if normalized_ecosystem == "yarn":
            if project_text is None:
                raise ValueError("project_text (package.json) is required for the yarn ecosystem")
            if lock_text is None:
                raise ValueError("lock_text (yarn.lock) is required for the yarn ecosystem")
            return YarnRelationshipVersionResolver(lock_text, project_text)
        if normalized_ecosystem in {"pip", "pypi", "python"}:
            if lock_text is None:
                raise ValueError("requirements file content is required for the pip ecosystem")
            return PipRelationshipVersionResolver(
                lock_text,
                requirements_path=requirements_path,
                support_files=support_files,
                source_path=source_path,
                source_text=source_text,
            )
        if normalized_ecosystem == "poetry":
            if project_text is None:
                raise ValueError("project_text is required for the poetry ecosystem")
            if lock_text is None:
                raise ValueError("lock_text is required for the poetry ecosystem")
            return PoetryRelationshipVersionResolver(lock_text, project_text)
        if normalized_ecosystem == "nuget":
            if project_files is None:
                raise ValueError("project_files are required for the nuget ecosystem")
            return NuGetRelationshipVersionResolver(
                project_files,
                support_files=support_files,
            )
        raise ValueError(f"Unsupported relationship resolver ecosystem: {ecosystem}")
