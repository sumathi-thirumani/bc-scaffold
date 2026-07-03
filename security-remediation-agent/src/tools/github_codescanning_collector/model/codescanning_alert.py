from collections.abc import Iterable
from typing import Any

from pydantic import BaseModel

UNKNOWN_SEVERITY = "unknown"


class CodescanningAlert(BaseModel):
    number: int | None = None
    url: str = ""
    summary: str = ""
    severity: str = UNKNOWN_SEVERITY
    rule_id: str = ""
    tool: str = ""
    ecosystem: str = ""

    @classmethod
    def from_codescanning_alert(cls, alert: dict[str, Any]) -> "CodescanningAlert | None":
        rule = alert.get("rule") or {}
        tool = alert.get("tool") or {}
        location = alert.get("location") or {}
        if not rule.get("name"):
            return None

        return cls(
            number=alert.get("number"),
            url=alert.get("html_url", ""),
            summary=rule.get("description", ""),
            severity=alert.get("security_severity_level", UNKNOWN_SEVERITY).lower(),
            rule_id=rule.get("id"),
            tool=tool.get("name", ""),
            ecosystem=location.get("path", ""),
        )


def build_alerts_by_package(alerts: Iterable[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    alerts_by_package: dict[str, list[dict[str, Any]]] = {}

    for alert in alerts:
        dependency = alert.get("dependency") or {}
        package = dependency.get("package") or {}
        package_name = package.get("name", "").lower()
        vulnerability_alert = CodescanningAlert.from_codescanning_alert(alert)
        if not package_name or vulnerability_alert is None:
            continue

        alerts_by_package.setdefault(package_name, []).append(
            vulnerability_alert.model_dump()
        )

    return alerts_by_package
