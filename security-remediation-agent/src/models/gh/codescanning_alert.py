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
            severity=(alert.get("security_severity_level") or UNKNOWN_SEVERITY).lower(),
            rule_id=rule.get("id") or "",
            tool=tool.get("name", ""),
            ecosystem=location.get("path", ""),
        )
