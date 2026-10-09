import logging

from ..agents.vulnerability_reviewer_agent import VulnerabilityReviewerAgent
from ..models.remediation_plan import RemediationPlan
from ..models.security_findings import SecurityFindings
from ..models.security_package_triage import SecurityPackageTriage
from ..models.security_remediation_context import SecurityRemediationContext

logger = logging.getLogger(__name__)

class SecurityOrchestrator:

    def __init__(
        self,
        vulnerabilityCollectorAgent,
        vulnerabilityTriageAgent,
        remediationPlanningAgent,
        reviewer=None,
        reporter=None,
    ) -> None:
        self.vulnerability_collector = vulnerabilityCollectorAgent
        self.triager = vulnerabilityTriageAgent
        self.remediation_planner = remediationPlanningAgent
        recommendation_resolver = getattr(
            vulnerabilityTriageAgent,
            "package_recommendation_resolver",
            None,
        )
        resolver_factory = getattr(recommendation_resolver, "resolver_factory", None)
        self.reviewer = reviewer or VulnerabilityReviewerAgent(
            resolver_factory=resolver_factory,
        )
        self.reporter = reporter

    async def run(self, repo: dict[str, str]) -> RemediationPlan:
        logger.info("Orchestration started for %s", repo) 
        #Context object
        remediation_context = SecurityRemediationContext(
                    total_vulnerabilities=0,
                    total_code_scanning_alerts=0,
                    total_reviewed_prs=0, 
                    total_ignored_prs=0,
                    total_remediation_prs=0
                )
        # ── Step 1: Collect ────────────────────────────────────────────────────
        findings = await self._collect(repo, remediation_context)

        if findings.is_empty():
            logger.info("No vulnerabilities found for %s", repo)
            return RemediationPlan(summary=remediation_context)

        logger.info(
            "Collected %d findings for %s (Dependabot: %d, retained code-scanning: %d)",
            len(findings.dependabot_alerts) + len(findings.codescanning_alerts),
            repo,
            len(findings.dependabot_alerts),
            len(findings.codescanning_alerts),
        )
        
        # ── Step 2: Triage ─────────────────────────────────────────────────────
        triage_items = await self._triage(repo, findings, remediation_context)

        logger.info("Triaged %d package(s) for %s", len(triage_items), repo)

        remediation_plan = await self._plan(triage_items, remediation_context, repo)
        remediation_plan = await self._review(remediation_plan, repo)
        await self._report(remediation_plan, repo)
        logger.info("Orchestration completed for %s", repo)
        return remediation_plan

# ── Private step methods ───────────────────────────────────────────────────

    async def _collect(
        self,
        repo: dict[str, str],
        context: SecurityRemediationContext,
    ) -> SecurityFindings:
        try:
            return await self.vulnerability_collector.collect(repo, context)
        except Exception as e:
            logger.error("Collection failed for %s: %s", repo, e)
            raise OrchestrationError("collect", repo, e) from e

    async def _triage(
        self,
        repo: dict[str, str],
        security_findings: SecurityFindings,
        context: SecurityRemediationContext,
    ) -> list[SecurityPackageTriage]:
        try:
            return await self.triager.triage(repo, security_findings, context)
        except Exception as e:
            logger.error("Triage failed for %s: %s", repo, e)
            raise OrchestrationError("triage", repo, e) from e

    async def _plan(
        self,
        triage_items: list[SecurityPackageTriage],
        context: SecurityRemediationContext,
        repo: dict[str, str],
    ) -> RemediationPlan:
        try:
            return await self.remediation_planner.plan(triage_items, context, repo)
        except Exception as e:
            logger.error("Remediation planning failed: %s", e)
            raise OrchestrationError("remediation", None, e) from e

    async def _review(
        self,
        remediation_plan: RemediationPlan,
        repo: dict[str, str],
    ) -> RemediationPlan:
        if self.reviewer is None:
            return remediation_plan
        try:
            return await self.reviewer.review(remediation_plan, repo)
        except Exception as e:
            logger.error("Remediation review failed for %s: %s", repo, e)
            raise OrchestrationError("review", repo, e) from e

    async def _report(
        self,
        remediation_plan: RemediationPlan,
        repo: dict[str, str],
    ) -> None:
        if self.reporter is None:
            return
        try:
            await self.reporter.report(remediation_plan, repo)
        except Exception as e:
            logger.error("Remediation report generation failed for %s: %s", repo, e)
            raise OrchestrationError("report", repo, e) from e

# ── Error ──────────────────────────────────────────────────────────────────────

class OrchestrationError(Exception):
    def __init__(self, step: str, repo: str | None, cause: Exception) -> None:
        self.step  = step
        self.repo  = repo
        self.cause = cause
        super().__init__(f"Orchestration failed at step='{step}' repo={repo}: {cause}")
