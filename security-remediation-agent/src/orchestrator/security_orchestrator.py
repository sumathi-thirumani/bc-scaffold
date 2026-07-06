import logging
from datetime import datetime
from typing import Protocol, runtime_checkable

from ..models.security_findings import SecurityFindings
from ..models.security_package_triage import SecurityPackageTriage
from ..models.remediation_plan_bundle import RemediationPlanBundle

logger = logging.getLogger(__name__)

class SecurityOrchestrator:

    def __init__(
        self,
        vulnerabilityCollectorAgent,
        vulnerabilityTriageAgent,
        remediationPlanningAgent,
        reviewer,
        reporter,
    ) -> None:
        self.vulnerability_collector = vulnerabilityCollectorAgent
        self.triager = vulnerabilityTriageAgent
        self.remediation_planner = remediationPlanningAgent
        self.reviewer = reviewer
        self.reporter = reporter

    async def run(self, repo: str) -> None:
        started_at = datetime.utcnow()
        logger.info("Orchestration started for %s", repo)

        # ── Step 1: Collect ────────────────────────────────────────────────────
        findings = await self._collect(repo)

        if findings.is_empty():
            logger.info("No vulnerabilities found for %s", repo)
            #return OrchestrationReport.empty(repo)

        logger.info(
            "Collected %d findings for %s",
            len(findings.dependabot_alerts) + len(findings.codescanning_alerts),
            repo,
        )

        # ── Step 2: Triage ─────────────────────────────────────────────────────
        triage_result = await self._triage(repo, findings)
        logger.info("Triage complete — %d packages", len(triage_result))

        # ── Step 3: Build remediation plans ────────────────────────────────────
        bundle = await self._plan(triage_result)
        logger.info("Remediation bundle: %s", bundle.summary())

        # # ── Step 4: LLM Review ─────────────────────────────────────────────────────
        # review = await self._review(bundle)
        # logger.info(
        #     "Review complete — approved=%d flagged=%d",
        #     len(review.approved),
        #     len(review.flagged),
        # )

        # # ── Step 5: Report ─────────────────────────────────────────────────────
        # report = await self._report(review)
        # report.started_at  = started_at
        # report.finished_at = datetime.utcnow()

        # logger.info("Orchestration complete: %s", report.summary())
        return bundle

# ── Private step methods ───────────────────────────────────────────────────

    async def _collect(self, repo: str) -> SecurityFindings:
        try:
            return await self.vulnerability_collector.collect(repo)
        except Exception as e:
            logger.error("Collection failed for %s: %s", repo, e)
            raise OrchestrationError("collect", repo, e) from e

    async def _triage(self, repo: str, SecurityFindings: SecurityFindings) -> SecurityPackageTriage:
        try:
            return await self.triager.triage(repo, SecurityFindings)
        except Exception as e:
            logger.error("Triage failed for %s: %s", repo, e)
            raise OrchestrationError("triage", repo, e) from e

    async def _plan(self, triage_result: SecurityPackageTriage) -> RemediationPlanBundle:
        try:
            return await self.remediation_planner.plan(triage_result)            
        except Exception as e:
            logger.error("Remediation planning failed: %s", e)
            raise OrchestrationError("remediation", None, e) from e

    # async def _review(self, bundle: RemediationPlanBundle) -> ReviewResult:
    #     try:
    #         return await self.review_agent.review(bundle)
    #     except Exception as e:
    #         logger.error("Review failed: %s", e)
    #         raise OrchestrationError("review", None, e) from e

    # async def _report(self, review: ReviewResult) -> OrchestrationReport:
    #     try:
    #         return await self.reporter.report(review)
    #     except Exception as e:
    #         logger.error("Reporting failed: %s", e)
    #         raise OrchestrationError("report", None, e) from e


# ── Error ──────────────────────────────────────────────────────────────────────

class OrchestrationError(Exception):
    def __init__(self, step: str, repo: str | None, cause: Exception) -> None:
        self.step  = step
        self.repo  = repo
        self.cause = cause
        super().__init__(f"Orchestration failed at step='{step}' repo={repo}: {cause}")