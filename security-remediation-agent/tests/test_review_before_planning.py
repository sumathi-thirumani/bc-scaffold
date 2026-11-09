"""Compatibility review must feed the final planner, including newly added updates."""
import asyncio
from types import SimpleNamespace as NS
from unittest.mock import AsyncMock

import pytest

from src.models.remediation_plan import RemediationPlan
from src.models.security_findings import SecurityFindings
from src.orchestrator.security_orchestrator import OrchestrationError, SecurityOrchestrator


def test_review_precedes_planning_and_preserves_added_updates():
    events = []
    original = NS(ecosystem='npm', compatible_version='')
    added = NS(ecosystem='npm', compatible_version='4.0.0')
    orchestrator = object.__new__(SecurityOrchestrator)
    orchestrator.recommendation_resolver_factory = None
    orchestrator.verification_enabled = True
    orchestrator._collect = AsyncMock(return_value=SecurityFindings([object()], []))
    orchestrator._collect_artifacts = AsyncMock(return_value=NS(ref='feature'))
    orchestrator._triage = AsyncMock(return_value=[original])

    async def review(plan, repo, *, ref):
        events.append('review')
        assert ref == 'feature'
        original.compatible_version = '3.0.0'
        plan.remediation_plan_bundles[0].packages.append(added)
        return plan

    async def plan(items, context, repo, ref):
        events.append('plan')
        assert ref == 'feature'
        assert items == [original, added]
        assert items[0].compatible_version == '3.0.0'
        return RemediationPlan(summary=context)

    async def verify(plan, repo, ref):
        events.append('verify')
        return plan

    async def report(plan, repo, ref):
        events.append('report')

    orchestrator.reviewer = NS(review=review)
    orchestrator.remediation_planner = NS(plan=plan)
    orchestrator._verify = verify
    orchestrator._report = report
    asyncio.run(orchestrator.run({'owner': 'o', 'name': 'r'}))
    assert events == ['review', 'plan', 'verify', 'report']


def test_review_input_keeps_ecosystems_separate():
    orchestrator = object.__new__(SecurityOrchestrator)
    items = [NS(ecosystem='NPM'), NS(ecosystem='pip'), NS(ecosystem='npm')]
    async def review(plan, repo, *, ref):
        assert [(b.ecosystem, len(b.packages)) for b in plan.remediation_plan_bundles] == [('npm', 2), ('pip', 1)]
        return plan
    orchestrator.reviewer = NS(review=review)
    result = asyncio.run(orchestrator._review_triage(items, None, {}))
    assert result == [items[0], items[2], items[1]]


def test_review_failure_does_not_reach_planner():
    orchestrator = object.__new__(SecurityOrchestrator)
    orchestrator.reviewer = NS(review=AsyncMock(side_effect=ValueError('review failed')))
    with pytest.raises(OrchestrationError) as error:
        asyncio.run(orchestrator._review_triage([NS(ecosystem='npm')], None, {}))
    assert error.value.step == 'review'
