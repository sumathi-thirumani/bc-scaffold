from dataclasses import dataclass

from ..tools.github_codescanning_collector.model.codescanning_alert import CodescanningAlert
from ..tools.github_vulnerability_collector.model.vulnerability_alert import VulnerabilityAlert

@dataclass
class SecurityFindings:
    dependabot_alerts: list[VulnerabilityAlert]
    codescanning_alerts: list[CodescanningAlert]

    def is_empty(self) -> bool:
        return not self.dependabot_alerts and not self.codescanning_alerts
