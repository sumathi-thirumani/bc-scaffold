import logging

from ..agents.remediation_artifact_agent import RemediationArtifactAgent
from ..agents.remediation_verification_agent import RemediationVerificationAgent
from ..agents.artifact_collector_agent import ArtifactCollectorAgent
from ..agents.vulnerability_reviewer_agent import VulnerabilityReviewerAgent
from ..models.remediation_plan import RemediationPlan, RemeditionPackageBundle
from ..models.repository_artifacts import RepositoryArtifacts
from ..models.security_findings import SecurityFindings
from ..models.security_package_triage import SecurityPackageTriage
from ..models.security_remediation_context import RepositoryContext, SecurityRemediationContext
from ..models.security_remediation_constants import SecurityRemediationConstants

logger = logging.getLogger(__name__)

class SecurityOrchestrator:

    """Run remediation stages in order with shared repository inputs and context.

    Core idea: collect findings and artifacts, triage packages, review compatibility,
    plan Renovate groups, verify upgrade sets, then export final evidence. Each stage
    finishes before the next begins; failures identify the responsible step."""
    def __init__(
        self,
        vulnerabilityCollectorAgent,
        vulnerabilityTriageAgent,
        remediationPlanningAgent,
        reviewer=None,
        reporter=None,
        artifactCollectorAgent=None,
        verificationAgent=None,
        ecosystems=None,
        verification_enabled: bool = True,
        additional_updates: bool = False,
        artifact_output: bool = True,
    ) -> None:
        self.ecosystems = frozenset(e.lower() for e in ecosystems) if ecosystems else None
        self.verification_enabled = verification_enabled
        self.vulnerability_collector = vulnerabilityCollectorAgent
        self.triager = vulnerabilityTriageAgent
        self.remediation_planner = remediationPlanningAgent
        # Share one ManifestTool per run: prefer the triager's so the collector's
        # prefetch warms the cache the resolvers read from.
        self.artifact_collector = artifactCollectorAgent or ArtifactCollectorAgent(
            manifest_tool=getattr(vulnerabilityTriageAgent, "manifest_tool", None),
        )
        if getattr(remediationPlanningAgent, "manifest_tool", False) is None:
            remediationPlanningAgent.manifest_tool = self.artifact_collector.manifest_tool
        recommendation_resolver = getattr(
            vulnerabilityTriageAgent,
            "package_recommendation_resolver",
            None,
        )
        resolver_factory = getattr(recommendation_resolver, "resolver_factory", None)
        self.recommendation_resolver_factory = resolver_factory
        self.reviewer = reviewer or VulnerabilityReviewerAgent(
            resolver_factory=resolver_factory,
            manifest_tool=self.artifact_collector.manifest_tool,
            additional_updates=additional_updates,
        )
        self.verifier = verificationAgent if verificationAgent is not None else RemediationVerificationAgent(
            manifest_tool=self.artifact_collector.manifest_tool,
        )
        if getattr(self.verifier, "manifest_tool", False) is None:
            self.verifier.manifest_tool = self.artifact_collector.manifest_tool
        self.reporter = None if not artifact_output else (
            reporter if reporter is not None else RemediationArtifactAgent(
                manifest_tool=self.artifact_collector.manifest_tool,
            )
        )
        if getattr(self.reporter, "manifest_tool", False) is None:
            self.reporter.manifest_tool = self.artifact_collector.manifest_tool

    async def run(self, repo: dict[str, str] | RepositoryContext) -> RemediationPlan:
        """Execute the ordered pipeline and return the same final plan that is reported."""
        if isinstance(repo, RepositoryContext):
            repo = {"owner": repo.owner, "name": repo.repo, "ref": repo.ref}
        if self.recommendation_resolver_factory is not None:
            self.recommendation_resolver_factory.begin_run()
        logger.info("Orchestration started for %s", repo) 
        #Context object
        remediation_context = SecurityRemediationContext(
                    total_vulnerabilities=0,
                    total_code_scanning_alerts=0,
                    total_reviewed_prs=0, 
                    total_ignored_prs=0,
                    total_remediation_prs=0
                )
        findings = await self._collect(repo, remediation_context)

        artifacts = await self._collect_artifacts(repo, findings, remediation_context)

        if findings.is_empty():
            logger.info("No vulnerabilities found for %s", repo)
            empty_plan = RemediationPlan(summary=remediation_context)
            await self._report(empty_plan, repo, artifacts.ref)
            return empty_plan

        triage_items = await self._triage(
            repo, findings, remediation_context, artifacts
        )

        logger.info("Triaged %d package(s) for %s", len(triage_items), repo)

        triage_items = await self._review_triage(triage_items, remediation_context, repo, artifacts.ref)
        remediation_plan = await self._plan(triage_items, remediation_context, repo, artifacts.ref)
        if self.verification_enabled:
            remediation_plan = await self._verify(remediation_plan, repo, artifacts.ref)
        else:
            logger.info("Remediation verification disabled by configuration")
        populate_targets = getattr(self.remediation_planner, "populate_upgrade_targets", None)
        if callable(populate_targets):
            populate_targets(remediation_plan)
        await self._report(remediation_plan, repo, artifacts.ref)
        for bundle in remediation_plan.remediation_plan_bundles:
            logger.info("Remediation bundle: %s--%s", bundle.ecosystem, bundle.groupName)
            for package in bundle.packages:
                if package.is_update:
                    for recommendation in package.package_upgrade_recommendations:
                        logger.info(
                            "Additional update %s: current=%s, compatible=%s, verified=%s",
                            recommendation.package, recommendation.from_version,
                            package.compatible_version(recommendation.package) or "unavailable",
                            package.verified_version(recommendation.package) or "unverified",
                        )
                    continue
                logger.info(
                    "%s dependency %s: vulnerabilities=%d, PR available=%s, vulnerable range=%s, current=%s, fixed=%s",
                    "Transitive" if package.istransitive else "Direct", package.package,
                    len(package.vulnerabilities), package.is_pull_available,
                    package.vulnerablility_version_range, package.current_version,
                    package.vulnerablility_fixed_version,
                )
                if package.istransitive:
                    for occurrence in package.transitive_dependency_occurrences:
                        logger.info(
                            "Transitive occurrence %s@%s: manifest=%s, introducers=%s",
                            occurrence.package, occurrence.version, occurrence.manifest_path,
                            ", ".join(f"{parent.package}@{parent.version}" for parent in occurrence.introducers),
                        )
                    for recommendation in package.package_upgrade_recommendations:
                        logger.info(
                            "Parent upgrade %s: current=%s, minimum=%s, highest=%s, compatible=%s, verified=%s, "
                            "verification notes=%s",
                            recommendation.package, recommendation.from_version,
                            recommendation.minimum_patched_version, recommendation.highest_stable_version,
                            package.compatible_version(recommendation.package),
                            package.verified_version(recommendation.package),
                            "; ".join(
                                f"{candidate.version} {candidate.verification_status}: {candidate.verification_message}"
                                for candidate in recommendation.qualifying_upgrade_versions
                                if candidate.verification_message
                            ) or "none",
                        )
        logger.info("Orchestration completed for %s", repo)
        return remediation_plan


    @staticmethod
    def _validate_plan(plan, source: str) -> RemediationPlan:
        if not isinstance(plan, RemediationPlan):
            raise TypeError(f"{source} must return RemediationPlan, got {type(plan).__name__}")
        if not isinstance(plan.remediation_plan_bundles, list):
            raise TypeError(
                f"{source} returned remediation_plan_bundles as "
                f"{type(plan.remediation_plan_bundles).__name__}; expected a list of bundles. "
                "Do not assign a RemediationPlan to remediation_plan_bundles."
            )
        return plan

    async def _collect(
        self,
        repo: dict[str, str],
        context: SecurityRemediationContext,
    ) -> SecurityFindings:
        try:
            findings = await self.vulnerability_collector.collect(repo, context)
        except Exception as e:
            logger.error("Collection failed for %s: %s", repo, e)
            raise OrchestrationError("collect", repo, e) from e
        return self._filter_ecosystems(findings)

    def _filter_ecosystems(self, findings: SecurityFindings) -> SecurityFindings:
        if not self.ecosystems:
            return findings
        in_scope = lambda alert: (alert.ecosystem or "").lower() in self.ecosystems
        filtered = SecurityFindings(
            dependabot_alerts=[a for a in findings.dependabot_alerts if in_scope(a)],
            # Code-scanning alerts carry no ecosystem, so the filter does not apply to them.
            codescanning_alerts=list(findings.codescanning_alerts),
        )
        dropped: dict[str, int] = {}
        for alert in findings.dependabot_alerts:
            if not in_scope(alert):
                dropped[alert.ecosystem or "unknown"] = dropped.get(alert.ecosystem or "unknown", 0) + 1
        logger.info(
            "Ecosystem filter %s kept %d of %d Dependabot alert(s); excluded by ecosystem: %s",
            sorted(self.ecosystems), len(filtered.dependabot_alerts), len(findings.dependabot_alerts),
            dropped or "none",
        )
        kept = {(a.ecosystem or "").lower() for a in filtered.dependabot_alerts}
        if self.ecosystems != SecurityRemediationConstants.SUPPORTED_ECOSYSTEMS:
            for name in sorted(self.ecosystems - kept):
                logger.info("Selected ecosystem %s has no open alerts; skipping", name)
        return filtered

    async def _collect_artifacts(
        self,
        repo: dict[str, str],
        security_findings: SecurityFindings,
        context: SecurityRemediationContext,
    ) -> RepositoryArtifacts:
        try:
            return await self.artifact_collector.collect(repo, security_findings, context)
        except Exception as e:
            logger.error("Artifact collection failed for %s: %s", repo, e)
            raise OrchestrationError("artifacts", repo, e) from e

    async def _triage(
        self,
        repo: dict[str, str],
        security_findings: SecurityFindings,
        context: SecurityRemediationContext,
        artifacts: RepositoryArtifacts,
    ) -> list[SecurityPackageTriage]:
        try:
            return await self.triager.triage(
                repo,
                security_findings,
                context,
                pull_requests=artifacts.pull_requests,
                ref=artifacts.ref,
            )
        except Exception as e:
            logger.error("Triage failed for %s: %s", repo, e)
            raise OrchestrationError("triage", repo, e) from e

    async def _plan(
        self,
        triage_items: list[SecurityPackageTriage],
        context: SecurityRemediationContext,
        repo: dict[str, str],
        ref: str | None = None,
    ) -> RemediationPlan:
        try:
            result = await self.remediation_planner.plan(triage_items, context, repo, ref=ref)
            return self._validate_plan(result, "planner")
        except Exception as e:
            logger.error("Remediation planning failed: %s", e)
            raise OrchestrationError("remediation", None, e) from e

    async def _review_triage(self, triage_items, context, repo, ref=None):
        """Review before Renovate grouping, retaining any additional update findings.

        Reviewers consume plans, so provide temporary ecosystem containers only.
        The planner owns final grouping and target consolidation after review.
        """
        by_ecosystem = {}
        for item in triage_items:
            by_ecosystem.setdefault(item.ecosystem.lower(), []).append(item)
        review_input = RemediationPlan(
            summary=context,
            remediation_plan_bundles=[
                RemeditionPackageBundle(ecosystem=ecosystem, groupName="default",
                                        severity="unknown", packages=items)
                for ecosystem, items in by_ecosystem.items()
            ],
        )
        reviewed = await self._review(review_input, repo, ref)
        return [item for bundle in reviewed.remediation_plan_bundles for item in bundle.packages]

    async def _review(
        self,
        remediation_plan: RemediationPlan,
        repo: dict[str, str],
        ref: str | None = None,
    ) -> RemediationPlan:
        if self.reviewer is None:
            return remediation_plan
        try:
            result = await self.reviewer.review(remediation_plan, repo, ref=ref)
            return self._validate_plan(result, "reviewer")
        except Exception as e:
            logger.error("Remediation review failed for %s: %s", repo, e)
            raise OrchestrationError("review", repo, e) from e

    async def _verify(
        self,
        remediation_plan: RemediationPlan,
        repo: dict[str, str],
        ref: str | None = None,
    ) -> RemediationPlan:
        try:
            result = await self.verifier.verify(remediation_plan, repo, ref=ref)
            return self._validate_plan(result, "verifier")
        except Exception as exc:
            logger.error("Remediation verification failed for %s: %s", repo, exc)
            raise OrchestrationError("verify", repo, exc) from exc

    async def _report(
        self,
        remediation_plan: RemediationPlan,
        repo: dict[str, str],
        ref: str | None = None,
    ) -> None:
        if self.reporter is None:
            return
        try:
            await self.reporter.report(remediation_plan, repo, ref=ref)
        except Exception as e:
            logger.error("Remediation report generation failed for %s: %s", repo, e)
            raise OrchestrationError("report", repo, e) from e


class OrchestrationError(Exception):
    """Attach the failed pipeline step and repository context to the original exception."""
    def __init__(self, step: str, repo: str | None, cause: Exception) -> None:
        self.step  = step
        self.repo  = repo
        self.cause = cause
        super().__init__(f"Orchestration failed at step='{step}' repo={repo}: {cause}")
