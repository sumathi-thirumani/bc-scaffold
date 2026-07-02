# Dependency Graph Refresh Workflow

`dependency-graph-refresh.yml` is a reusable GitHub Actions workflow that generates SBOMs and refreshes the GitHub Dependency Graph for detected ecosystem directories. It can also be run manually to test SBOM generation for a repository path.

## What it does

1. Checks out the repository.
2. Builds a scan matrix from the configured `source_path`.
3. Generates CycloneDX and SPDX JSON SBOM files for each matrix entry.
4. Uses installed-environment CycloneDX generation for Python projects with `poetry.lock`, `requirements.txt`, or `[tool.poetry]`; all other targets use Syft directly.
5. Optionally uploads generated SBOM files as workflow artifacts.
6. Submits dependency information to the GitHub Dependency Graph for each matrix entry.

The SBOM generation and dependency graph refresh jobs both run as matrix jobs. Each selected target is processed independently with its own `scan_label`, `source`, and `output_prefix`.

## Triggers

The workflow supports two entry points:

| Trigger | Purpose |
| --- | --- |
| `workflow_call` | Allows other workflows in the same repository to reuse this workflow. |
| `workflow_dispatch` | Allows manual runs for testing or one-off refreshes. |

## Inputs

| Input | Required | Default | Description |
| --- | --- | --- | --- |
| `source_path` | No | `.` | Repository path or subdirectory to scan for ecosystem manifests. |
| `syft_version` | No | `v1.45.0` | Syft version used for filesystem SBOM generation and SPDX output. |
| `upload_artifacts` | No | `true` | Whether generated SBOM files are uploaded as workflow artifacts. |
| `artifact_prefix` | No | `sbom` | Prefix used for uploaded artifact names. |
| `artifact_retention_days` | No | `30` | Retention period for uploaded SBOM artifacts. |

## Permissions

The workflow requires:

```yaml
permissions:
  contents: write
```

This is needed for repository checkout and dependency graph snapshot submission.

## Jobs

| Job | Description |
| --- | --- |
| `prepare-matrix` | Resolves inputs, detects scan targets, and produces the matrix used by downstream jobs. |
| `generate-sbom` | Runs once per matrix entry and generates `.cyclonedx.json` and `.spdx.json` SBOM files. |
| `refresh-dependency-graph` | Runs once per matrix entry and submits dependency data to GitHub Dependency Graph. |

If no ecosystem manifests are detected, the matrix falls back to one generic filesystem scan for `source_path`.

## Scan target detection

The matrix builder scans `source_path` for package manifests and groups findings by manifest directory. Generated, vendored, cached, and workflow-only folders such as `.git`, `.github`, `node_modules`, `vendor`, `venv`, `.venv`, `dist`, and `build` are skipped.

Detected ecosystems include:

| Ecosystem | Manifest examples |
| --- | --- |
| `node` | `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `package.json` |
| `python` | `requirements*.txt`, `pyproject.toml`, `poetry.lock`, `Pipfile.lock`, `setup.py` |
| `java` | `pom.xml`, `build.gradle`, `build.gradle.kts`, `settings.gradle`, `settings.gradle.kts` |
| `dotnet` | `*.sln`, `*.csproj`, `*.fsproj`, `*.vbproj`, `Directory.Packages.props` |

Each matrix entry uses `dir:<manifest-directory>` as the Syft source and a stable label in this shape:

```text
filesystem-<ecosystems>-<relative-path>
```

## SBOM generation

The `generate-sbom` job runs the SBOM composite action once per matrix entry. The action installs the configured Syft version, derives deterministic CycloneDX metadata from the latest commit timestamp and `repository@sha@scan_label`, then writes:

```text
<matrix.output_prefix>.cyclonedx.json
<matrix.output_prefix>.spdx.json
```

For non-Python targets, Syft generates both files directly from `matrix.source`.

For Python targets with `poetry.lock`, `requirements.txt`, or `[tool.poetry]`, the generator creates temporary virtual environments, installs the project dependencies, generates CycloneDX from the installed Python environment, verifies that the CycloneDX file contains components, and generates SPDX JSON with Syft from the project directory.

After generation, the action normalizes only the CycloneDX file by sorting JSON keys and setting deterministic `metadata.timestamp` and `serialNumber` values.

## Artifact naming

When `upload_artifacts` is enabled, each matrix entry uploads both generated SBOM files:

```text
<artifact_prefix>-<github.run_id>-<matrix.scan_label>
```

Each artifact contains:

```text
<matrix.output_prefix>.cyclonedx.json
<matrix.output_prefix>.spdx.json
```

## Example caller workflow

```yaml
name: Refresh Dependency Graph

on:
  workflow_dispatch:
  push:
    branches:
      - main

jobs:
  refresh:
    uses: ./.github/workflows/dependency-graph-refresh.yml
    with:
      source_path: .
      syft_version: v1.45.0
      upload_artifacts: true
      artifact_prefix: sbom
      artifact_retention_days: 30
```

## Local action references

The workflow currently calls the composite actions from this repository with a hardcoded repository and branch reference:

```yaml
uses: sumathi-thirumani/bc-scaffold/.github/actions/<action-name>@feature/security-remediation
```

For a workflow that lives in the same repository as these composite actions, prefer local action paths so the workflow uses the checked-out revision from the current run:

```yaml
uses: ./.github/actions/<action-name>
```

## Manual run

Use the `workflow_dispatch` trigger to run this workflow directly from the GitHub Actions UI. Override `source_path` to test a specific subdirectory without changing caller workflows.

## Notes

- SBOM generation usually uses Syft directly, with a Python-specific path that generates CycloneDX from an installed dependency environment.
- SPDX output is generated with Syft directly and is not converted from CycloneDX.
- Deterministic metadata normalization currently applies to the CycloneDX output only.
- The dependency graph refresh step runs in a matrix and submits each scan target with a distinct correlator.
- Matrix detection is handled before fan-out because GitHub Actions requires matrix values to be known before matrix jobs start.
