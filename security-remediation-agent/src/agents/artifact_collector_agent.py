"""Collect repository artifacts (open PRs, declaration manifests) once per run."""

import asyncio
import logging
from typing import Any

from ..models.gh.pull_request_metadata import PullRequestMetadata
from ..models.repository_artifacts import RepositoryArtifacts
from ..models.security_findings import SecurityFindings
from ..models.security_remediation_context import (
    SecurityRemediationCache,
    SecurityRemediationContext,
)
from ..tools.ecosystem_manifest_tool import ManifestTool
from ..tools.pull_requests_tool import pull_requests_tool

logger = logging.getLogger(__name__)

class ArtifactCollectorAgent:
    """Fetch PRs and prefetch manifests into the run-scoped manifest cache.

    The ``ManifestTool`` owned here is meant to be shared by every downstream
    agent so each manifest is fetched from GitHub at most once per run.
    """

    def __init__(self, manifest_tool: ManifestTool | None = None) -> None:
        if manifest_tool is None:
            logger.debug("ArtifactCollectorAgent created its own ManifestTool; cache is not shared")
            manifest_tool = ManifestTool(cache=SecurityRemediationCache())
        self.manifest_tool = manifest_tool

    async def collect(
        self,
        repo: Any,
        findings: SecurityFindings,
        context: SecurityRemediationContext,
    ) -> RepositoryArtifacts:
        owner = repo["owner"] if isinstance(repo, dict) else repo.owner
        name = repo["name"] if isinstance(repo, dict) else repo.name

        # Pin the commit once; every downstream read uses this ref (None = unpinned run).
        ref = await self._safe_resolve_ref(owner, name)
        pull_requests, _ = await asyncio.gather(
            self._fetch_pull_requests(owner, name),
            self._safe_prefetch_manifests(owner, name, findings, ref),
        )
        context.total_reviewed_prs = len(pull_requests)

        return RepositoryArtifacts(
            owner=owner,
            repo=name,
            pull_requests=pull_requests,
            manifest_tool=self.manifest_tool,
            ref=ref,
        )

    async def _safe_resolve_ref(self, owner: str, repo: str) -> str | None:
        try:
            return await self.manifest_tool.resolve_ref(owner, repo)
        except Exception:
            logger.warning("Could not pin HEAD for %s/%s; running unpinned", owner, repo, exc_info=True)
            return None

    @staticmethod
    async def _fetch_pull_requests(owner: str, repo: str) -> list[PullRequestMetadata]:
        return await pull_requests_tool.ainvoke({"owner": owner, "repo": repo})

    async def _safe_prefetch_manifests(
        self, owner: str, repo: str, findings: SecurityFindings, ref: str | None = None,
    ) -> None:
        """Prefetch is a cache warm-up; it must never fail ``collect``."""
        try:
            await self._prefetch_manifests(owner, repo, findings, ref)
        except Exception:
            logger.warning("Manifest prefetch aborted for %s/%s", owner, repo, exc_info=True)

    async def _prefetch_manifests(
        self,
        owner: str,
        repo: str,
        findings: SecurityFindings,
        ref: str | None = None,
    ) -> None:
        """Warm the cache with raw manifests, lockfiles, and their companions.

        Collection deliberately does not parse repository files. Cache-only downstream
        resolvers parse the raw content only when they need structured data.
        """
        raw_paths: dict[str, None] = {}
        for alert in findings.dependabot_alerts:
            ecosystem = (alert.ecosystem or "").lower()
            if alert.manifest_path:
                raw_paths[alert.manifest_path.replace("\\", "/").strip("/")] = None
            declaration = self.manifest_tool.declaration_path(ecosystem, alert.manifest_path)
            if declaration:
                raw_paths[declaration] = None
            for raw in self.manifest_tool.triage_paths(ecosystem, alert.manifest_path):
                raw_paths[raw] = None

        results = await asyncio.gather(
            *(self.manifest_tool.get(owner, repo, path, ref) for path in raw_paths),
            return_exceptions=True,
        )
        labels = list(raw_paths)
        for label, result in zip(labels, results):
            if isinstance(result, Exception):
                logger.warning("Manifest prefetch failed for %s/%s %s: %s", owner, repo, label, result)
            elif isinstance(result, BaseException):
                raise result
