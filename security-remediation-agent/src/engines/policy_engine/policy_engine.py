import re
from itertools import zip_longest
from typing import Any

from ...tools.github_vulnerability_collector.model.vulnerability_alert import VulnerabilityAlert

SEVERITY_PRIORITY = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "unknown": 0,
}

HIGH_PRIORITY_SEVERITIES = {"critical", "high"}


class PolicyEngine:
    """
    Encapsulates all deterministic triage decision logic:
    - version selection
    - upgrade strategy
    - severity evaluation
    - transitive upgrade reasoning
    """

    # -------------------------
    # Severity logic
    # -------------------------

    def highest_severity(self, alerts: list[VulnerabilityAlert]) -> str:
        return max(
            (a.severity.lower() for a in alerts),
            key=lambda s: SEVERITY_PRIORITY.get(s, 0),
            default="unknown",
        )

    def alerts_to_prioritize(self, alerts: list[VulnerabilityAlert]) -> list[VulnerabilityAlert]:
        priority = [
            a for a in alerts
            if a.severity.lower() in HIGH_PRIORITY_SEVERITIES
        ]
        return priority if priority else alerts

    # -------------------------
    # Version extraction helpers
    # -------------------------

    def current_version_from_range(self, version_range: str) -> str:
        matches = re.findall(r"\d+(?:[.\-_+][0-9A-Za-z]+)*", version_range)
        return matches[0] if matches else ""

    def major_version(self, version: str) -> int | None:
        cleaned = re.sub(r"^[^0-9]*", "", version)
        major = re.split(r"[.\-+_]", cleaned)[0]
        return int(major) if major.isdigit() else None

    def version_sort_key(self, version: str) -> tuple[Any, ...]:
        parts = re.split(r"[.\-+_]", re.sub(r"^[^0-9]*", "", version))
        out: list[tuple[int, Any]] = []
        for p in parts:
            if p.isdigit():
                out.append((1, int(p)))
            elif p:
                out.append((0, p))
        return tuple(out)

    def compare_version_keys(self, a: tuple[Any, ...], b: tuple[Any, ...]) -> int:
        for x, y in zip_longest(a, b, fillvalue=(1, 0)):
            if x == y:
                continue
            return 1 if x > y else -1
        return 0

    def is_version_at_least(self, v: str, minimum: str) -> bool:
        if not v or not minimum:
            return False
        return self.compare_version_keys(
            self.version_sort_key(v),
            self.version_sort_key(minimum),
        ) >= 0

    # -------------------------
    # Core version decisioning
    # -------------------------

    def highest_fixed_version(self, alerts: list[VulnerabilityAlert]) -> str:
        versions = [a.first_patched for a in alerts if a.first_patched]
        return max(versions, key=self.version_sort_key) if versions else ""

    def current_major_from_alerts(self, alerts: list[VulnerabilityAlert]) -> int | None:
        for a in alerts:
            v = self.current_version_from_range(a.vulnerable_range)
            m = self.major_version(v)
            if m is not None:
                return m
        return None

    def has_high_priority_major_requirement(
        self,
        alerts: list[VulnerabilityAlert],
        current_major: int,
    ) -> bool:
        return any(
            a.severity.lower() in HIGH_PRIORITY_SEVERITIES
            and self.major_version(a.first_patched) not in (None, current_major)
            for a in alerts
        )

    def minimum_recommended_version(
        self,
        alerts: list[VulnerabilityAlert],
    ) -> str:
        required = self.highest_fixed_version(alerts)
        if not required:
            return ""

        current_major = self.current_major_from_alerts(alerts)
        required_major = self.major_version(required)

        if (
            current_major is None
            or required_major is None
            or required_major == current_major
        ):
            return required

        compatible = [
            a.first_patched
            for a in alerts
            if self.major_version(a.first_patched) == current_major
        ]

        if compatible and not self.has_high_priority_major_requirement(
            alerts, current_major
        ):
            return max(compatible, key=self.version_sort_key)

        return required

    # -------------------------
    # Upgrade classification
    # -------------------------

    def breaking_upgrade_version(
        self,
        alerts: list[VulnerabilityAlert],
        current_major: int | None,
    ) -> str:
        if current_major is None:
            return ""

        candidates = [
            a.first_patched
            for a in alerts
            if self.major_version(a.first_patched) not in (None, current_major)
        ]
        return max(candidates, key=self.version_sort_key) if candidates else ""

    def non_breaking_upgrade_version(
        self,
        alerts: list[VulnerabilityAlert],
        current_major: int | None,
    ) -> str:
        if current_major is None:
            return ""

        candidates = [
            a.first_patched
            for a in alerts
            if self.major_version(a.first_patched) == current_major
        ]
        return max(candidates, key=self.version_sort_key) if candidates else ""