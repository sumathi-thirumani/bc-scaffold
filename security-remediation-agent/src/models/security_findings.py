from dataclasses import dataclass

from .gh.codescanning_alert import CodescanningAlert
from .gh.vulnerability_alert import VulnerabilityAlert

@dataclass
class SecurityFindings:
    """Keep Dependabot and code-scanning results separate until triage combines their evidence."""
    dependabot_alerts: list[VulnerabilityAlert]
    codescanning_alerts: list[CodescanningAlert]

    def is_empty(self) -> bool:
        return not self.dependabot_alerts and not self.codescanning_alerts
