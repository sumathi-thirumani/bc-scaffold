"""Collect repository artifacts (open PRs, declaration manifests) once per run."""

import asyncio
import logging
from typing import Any

from ..models.gh.pull_request_metadata import PullRequestMetadata
from ..models.repository_artifacts import RepositoryArtifacts
from ..models.security_findings import SecurityFindings
from ..models.security_remediation_context import (
    SecurityRemediationContext,
)
from ..tools.ecosystem_manifest_tool import RENOVATE_CONFIG_PATHS, ManifestTool
from ..tools.pull_requests_tool import pull_requests_tool
from ..tools.repository_context_tool import get_repository_context

logger = logging.getLogger(__name__)

class ArtifactCollectorAgent:
    """Fetch PRs and prefetch manifests into the run-scoped manifest cache.

    The ``ManifestTool`` owned here is meant to be shared by every downstream
    agent so each manifest is fetched from GitHub at most once per run.
    """

    def __init__(self, manifest_tool: ManifestTool | None = None) -> None:
        if manifest_tool is None:
            logger.debug("ArtifactCollectorAgent created its own ManifestTool; cache is not shared")
            manifest_tool = ManifestTool()
        self.manifest_tool = manifest_tool

    async def collect(
        self,
        repo: Any,
        findings: SecurityFindings,
        context: SecurityRemediationContext,
    ) -> RepositoryArtifacts:
        owner = repo["owner"] if isinstance(repo, dict) else repo.owner
        name = (repo.get("name") or repo["repo"]) if isinstance(repo, dict) else repo.repo

        # Start each collection with a fresh cache and use the configured branch.
        self.manifest_tool.clear_cache()
        ref = repo.get("ref") if isinstance(repo, dict) else repo.ref
        if not ref:
            ref = (await get_repository_context(owner, name)).ref
        pull_requests, _ = await asyncio.gather(
            self._fetch_pull_requests(owner, name),
            self._safe_prefetch_manifests(owner, name, findings, ref),
        )
        context.total_reviewed_prs = len(pull_requests)

        for pull in pull_requests:
            logger.debug("Processing pull request: %s", pull.pr_number)
            logger.debug("Pull request version bumps: %s", pull.version_bumps)

        return RepositoryArtifacts(
            owner=owner,
            repo=name,
            pull_requests=pull_requests,
            manifest_tool=self.manifest_tool,
            ref=ref,
        )

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

    @staticmethod
    def _drop_alerts_for_missing_manifests(
        owner: str, repo: str, findings: SecurityFindings, tree: list[dict[str, str]],
    ) -> None:
        """Drop alerts whose manifest is not in the repository tree: they cannot be remediated.

        Dependabot can keep alerts for paths that do not exist at the base ref, for
        example from a dependency snapshot reporting root-relative paths."""
        files = {entry["path"] for entry in tree}
        if not files:
            return
        kept, skipped = [], []
        for alert in findings.dependabot_alerts:
            path = (alert.manifest_path or "").replace("\\", "/").strip("/")
            (kept if not path or path in files else skipped).append(alert)
        if skipped:
            logger.warning(
                "Skipped %d Dependabot alert(s) for %s/%s whose manifest is not in the repository: %s",
                len(skipped), owner, repo,
                ", ".join(sorted({a.manifest_path for a in skipped})),
            )
            findings.dependabot_alerts[:] = kept

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
        raw_paths: dict[str, None] = dict.fromkeys(RENOVATE_CONFIG_PATHS)
        for alert in findings.dependabot_alerts:
            ecosystem = (alert.ecosystem or "").lower()
            if alert.manifest_path:
                raw_paths[alert.manifest_path.replace("\\", "/").strip("/")] = None
            declaration = self.manifest_tool.declaration_path(ecosystem, alert.manifest_path)
            if declaration:
                raw_paths[declaration] = None
            for raw in self.manifest_tool.triage_paths(ecosystem, alert.manifest_path):
                raw_paths[raw] = None

        try:
            tree = await self.manifest_tool.repository_tree(owner, repo, ref)
        except (OSError, ValueError) as exc:
            logger.warning(
                "Could not list repository files for %s/%s; prefetching alert manifests only: %s",
                owner,
                repo,
                exc,
            )
        else:
            self._drop_alerts_for_missing_manifests(owner, repo, findings, tree)
            for entry in tree:
                path = entry["path"]
                if self.manifest_tool.is_dependency_manifest(path):
                    raw_paths[path] = None

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
