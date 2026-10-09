import re
from typing import Any

from ..models.gh.vulnerability_alert import VulnerabilityAlert

SEVERITY_PRIORITY = {
    "critical": 4,
    "high": 3,
    "moderate": 2,
    "medium": 2,
    "low": 1,
    "unknown": 0,
}


class PolicyEngine:
    """Deterministic triage decisions: severity ranking and fixed-version selection."""

    # -------------------------
    # Severity logic
    # -------------------------

    def highest_severity(self, alerts: list[VulnerabilityAlert]) -> str:
        return max(
            (a.severity.lower() for a in alerts),
            key=lambda s: SEVERITY_PRIORITY.get(s, 0),
            default="unknown",
        )

    # -------------------------
    # Version helpers
    # -------------------------

    def version_sort_key(self, version: str) -> tuple[Any, ...]:
        parts = re.split(r"[.\-+_]", re.sub(r"^[^0-9]*", "", version))
        out: list[tuple[int, Any]] = []
        for p in parts:
            if p.isdigit():
                out.append((1, int(p)))
            elif p:
                out.append((0, p))
        return tuple(out)

    # -------------------------
    # Core version decisioning
    # -------------------------

    def highest_fixed_version(self, alerts: list[VulnerabilityAlert]) -> str:
        versions = [a.first_patched for a in alerts if a.first_patched]
        return max(versions, key=self.version_sort_key) if versions else ""
