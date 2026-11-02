# Security and Vulnerability Remediation Scaffolding

Reusable automation for reviewing GitHub security findings and planning dependency upgrades across repositories.

The current Python workflow collects Dependabot and selected code-scanning findings, traces dependency relationships, matches existing bot PRs, groups remediation work, reviews compatible upgrade candidates, and verifies supported candidates through dependency resolution. It exports a complete remediation plan and Renovate rules for verified recommendations.

The pipeline is deterministic and does not require an LLM. Resolution verification checks dependency compatibility on the runner; application builds, tests, and security review remain part of the target project's release process.

## Documentation

- [Security Remediation Agent](security-remediation-agent/README.md): architecture diagram, workflow explanation, setup, usage, output formats, and tests.
- [Remediation verification](security-remediation-agent/src/engines/remediation_verification/README.md): supported engines, candidate requirements, and verification limits.

## Repository contents

| Location | Purpose |
| --- | --- |
| [security-remediation-agent/](security-remediation-agent/) | Python remediation pipeline and tests |
| [Remediation workflow](.github/workflows/security-vulnerability-remediation.yml) | GitHub Actions integration |
| [Workflow scripts](.github/scripts/security-remediation/) | Orchestrator invocation, output preparation, tracking issues, and summaries |
| [templates/](templates/) | CI, CD, and scanning templates |
| [examples/](examples/) | Example project files |

## Get started

Follow the [agent setup and run instructions](security-remediation-agent/README.md#run-locally). The CLI writes `remediation-plan.json` and `renovate.json5` in the current working directory and prints the returned plan as JSON.

## Contributing

Open an issue to report a bug or propose a change. Submit a pull request with relevant validation; test commands are listed in the [agent README](security-remediation-agent/README.md#tests).
