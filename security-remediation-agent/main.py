import argparse
import asyncio
import json
import sys
from dataclasses import asdict, is_dataclass
from datetime import date, datetime
from enum import Enum
from typing import Any

from src.agents.remediation_planner_agent import RemediationPlannerAgent
from src.agents.vulnerability_collector_agent import VulnerabilityCollectorAgent
from src.agents.vulnerability_triage_agent import VulnerabilityTriageAgent
from src.orchestrator.security_orchestrator import SecurityOrchestrator


def to_jsonable(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return to_jsonable(asdict(value))
    if hasattr(value, "model_dump"):
        return to_jsonable(value.model_dump())
    if isinstance(value, dict):
        return {str(key): to_jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [to_jsonable(item) for item in value]
    return value


async def async_main() -> None:
    parser = argparse.ArgumentParser(description="Run security remediation orchestration.")
    parser.add_argument("--owner", required=True, help="Repository owner or organization.")
    parser.add_argument("--repo",  required=True, help="Repository name.")
    args = parser.parse_args(normalize_duplicated_invocation(sys.argv[1:]))

    repo = {"owner": args.owner, "name": args.repo}

    orchestrator = SecurityOrchestrator(
        VulnerabilityCollectorAgent(),
        VulnerabilityTriageAgent(),
        RemediationPlannerAgent(),
        reviewer=None,
        reporter=None,
    )

    result = await orchestrator.run(repo)
    print(json.dumps(to_jsonable(result), indent=2, sort_keys=True))


def normalize_duplicated_invocation(argv: list[str]) -> list[str]:
    for index in range(len(argv) - 1):
        if argv[index].endswith(".py") and argv[index + 1].endswith(".py"):
            return argv[:index] + argv[index + 2:]
    return argv


def main() -> None:
    asyncio.run(async_main())


if __name__ == "__main__":
    main()