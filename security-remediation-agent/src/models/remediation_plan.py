from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any



# ── Enums ──────────────────────────────────────────────────────────────────────

class FixClass(str, Enum):
    NO_FIX_AVAILABLE      = "NO_FIX_AVAILABLE"
    NON_BREAKING_BUMP     = "NON_BREAKING_BUMP"
    BREAKING_BUMP         = "BREAKING_BUMP"
    PARTIAL_FIX_AVAILABLE = "PARTIAL_FIX_AVAILABLE"


class ActionType(str, Enum):
    ROLLUP_PR      = "rollup_pr"        # non-breaking + PR exists → grouped
    STANDALONE_PR  = "standalone_pr"    # breaking + PR exists → separate
    PLACEHOLDER_PR = "placeholder_pr"   # no PR exists → markdown stub
    OPEN_ISSUE     = "open_issue"       # no fix available


class CodingAgent(str, Enum):
    COPILOT = "copilot"
    LLM     = "llm"
    NONE    = "none"


# ── Sub-models ─────────────────────────────────────────────────────────────────

@dataclass
class PackageContext:
    name: str
    ecosystem: str
    current_version_range: str
    remediated_version: str
    effective_severity: str            # highest across all vulnerabilities
    relationship: str            # "direct" | "transitive" | "indirect" | "unknown"
    transitive_source_package: list[str]
    unique_ghsas: list[str]


@dataclass
class FixPlan:
    fix_class: FixClass
    non_breaking_fix: str | None       # "" normalized to None
    breaking_fix: str | None
    upgrade_version: str
    partial_fix_available: bool
    patch_available: bool


@dataclass
class ActionPlan:
    action_type: ActionType
    pull_url: str                        # existing PR url if available
    pr_number: int | None              # existing PR number if available
    placeholder_markdown: str          # populated when action_type = PLACEHOLDER_PR
    target_package: str                = ""  # package the action actually bumps —
                                              # == package.name for direct findings,
                                              # == the source package for transitive ones


@dataclass
class PlanState:
    assigned_agent: CodingAgent        = CodingAgent.NONE
    agent_assigned_at: datetime | None = None
    autofix_attempted: bool            = False
    issue_id: str                      = ""
    issue_url: str                     = ""
    recheck_at: datetime | None        = None


@dataclass
class AuditEntry:
    timestamp: str
    agent: str
    action: str
    detail: str


# ── Main model ─────────────────────────────────────────────────────────────────

@dataclass
class RemediationPlan:
    plan_id:    str
    created_at: datetime
    package:    PackageContext
    fix:        FixPlan
    action:     ActionPlan
    state:      PlanState
    audit:      list[AuditEntry] = field(default_factory=list)