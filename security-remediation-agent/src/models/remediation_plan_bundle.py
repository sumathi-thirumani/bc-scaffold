from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator

from ..models.remediation_plan import ActionType, FixClass, RemediationPlan   # ← the real RemediationPlan


def _impact_for(plan: RemediationPlan) -> str:
    """
    Breaking-ness is carried on FixPlan.fix_class, not on ActionPlan.
    PARTIAL_FIX_AVAILABLE means a breaking fix was the one actually routed
    to (no non-breaking PR was available — see derive_action_type), so it
    counts as Breaking impact for grouping/reporting purposes.
    """
    breaking = plan.fix.fix_class in (FixClass.BREAKING_BUMP, FixClass.PARTIAL_FIX_AVAILABLE)
    return "Breaking" if breaking else "Non-Breaking"


@dataclass
class PlaceholderSubgroup:
    """
    All PLACEHOLDER_PR plans within a severity group that share the same
    impact (Breaking / Non-Breaking). Each subgroup gets its own tracking
    PR — never a merged 'Non-Breaking + Breaking' PR — and that PR's body
    IS plan.action.placeholder_markdown joined together; there is no
    separate markdown artifact to keep in sync.
    """
    impact: str
    plans: list[RemediationPlan] = field(default_factory=list)

    @property
    def packages(self) -> list[str]:
        return [p.package.name for p in self.plans]

    @property
    def combined_markdown(self) -> str:
        return "\n\n---\n\n".join(p.action.placeholder_markdown for p in self.plans)

    def apply_tracking_pr(self, pull_url: str, pr_number: int) -> None:
        """
        Write the created/updated tracking PR back onto every plan in this
        subgroup, so downstream report rendering reads pull_url/pr_number
        directly off the plan like it already does for matched remediations.
        """
        for plan in self.plans:
            plan.action.pull_url = pull_url
            plan.action.pr_number = pr_number


@dataclass
class RemediationPlanGroup:                             # ← fix 1
    severity: str
    plans: list[RemediationPlan] = field(default_factory=list)

    def add(self, plan: RemediationPlan) -> None:
        self.plans.append(plan)

    def __len__(self) -> int:
        return len(self.plans)

    def placeholder_subgroups(self) -> list[PlaceholderSubgroup]:
        """
        Split this severity group's PLACEHOLDER_PR plans by impact, so the
        report (and the tracking-PR creation step) never has to merge
        Breaking and Non-Breaking fixes into a single row/PR again.
        """
        buckets: dict[str, PlaceholderSubgroup] = {}
        for plan in self.plans:
            if plan.action.action_type != ActionType.PLACEHOLDER_PR:
                continue
            impact = _impact_for(plan)
            if impact not in buckets:
                buckets[impact] = PlaceholderSubgroup(impact=impact)
            buckets[impact].plans.append(plan)

        # Non-Breaking first — lower risk, surfaced before Breaking.
        return sorted(buckets.values(), key=lambda g: g.impact != "Non-Breaking")


@dataclass
class RemediationPlanBundle:                            # ← fix 2
    groups: dict[str, RemediationPlanGroup] = field(default_factory=dict)

    _SEVERITY_ORDER = ["critical", "high", "medium", "low", "unknown"]

    @classmethod
    def from_plans(cls, plans: list[RemediationPlan]) -> RemediationPlanBundle:
        bundle = cls()
        for plan in plans:
            bundle.add(plan)
        return bundle

    def add(self, plan: RemediationPlan) -> None:
        severity = plan.package.effective_severity.lower()
        if severity not in self.groups:
            self.groups[severity] = RemediationPlanGroup(severity=severity)
        self.groups[severity].add(plan)

    def by_severity(self, severity: str) -> RemediationPlanGroup | None:
        return self.groups.get(severity.lower())

    def ordered(self) -> Iterator[RemediationPlanGroup]:
        for sev in self._SEVERITY_ORDER:
            if sev in self.groups:
                yield self.groups[sev]

    def all_placeholder_subgroups(self) -> list[PlaceholderSubgroup]:
        """
        Collect placeholder subgroups across every severity, merged by
        impact. This is what tracking-PR creation should iterate over —
        one tracking PR per impact, not per (severity, impact) pair, so
        e.g. all Non-Breaking placeholders land in one PR regardless of
        whether they're 'high' or 'medium' severity.
        """
        merged: dict[str, PlaceholderSubgroup] = {}
        for group in self.groups.values():
            for subgroup in group.placeholder_subgroups():
                if subgroup.impact not in merged:
                    merged[subgroup.impact] = PlaceholderSubgroup(impact=subgroup.impact)
                merged[subgroup.impact].plans.extend(subgroup.plans)
        return sorted(merged.values(), key=lambda g: g.impact != "Non-Breaking")

    def summary(self) -> dict[str, int]:
        return {sev: len(group) for sev, group in self.groups.items()}

    def __len__(self) -> int:
        return sum(len(g) for g in self.groups.values())