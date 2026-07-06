from ..models.remediation_plan_bundle import RemediationPlanBundle
from ..models.security_package_triage import SecurityPackageTriage
from ..tools.remediation_planning_assistant.remediation_planning_tool import (
    build_remediation_plan,
)


class RemediationPlannerAgent:
    def __init__(self) -> None:
        self.tools = [build_remediation_plan]

    async def plan(
        self,
        triage_result: list[SecurityPackageTriage],
    ) -> RemediationPlanBundle:
        plans = [
            await build_remediation_plan.ainvoke({"pkg": package_triage})
            for package_triage in triage_result
        ]
        return RemediationPlanBundle.from_plans(plans)
