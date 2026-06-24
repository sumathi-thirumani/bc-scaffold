# Dependency Graph Refresh Workflow

`dependency-graph-refresh.yml` is a reusable GitHub Actions workflow that generates SBOMs and refreshes the GitHub Dependency Graph for detected ecosystem directories.

## What it does

1. Checks out the repository.
2. Builds a scan matrix from the configured `source_path`.
3. Generates CycloneDX and SPDX SBOM files for each matrix entry using Syft.
4. Optionally uploads generated SBOM files as workflow artifacts.
5. Submits dependency information to the GitHub Dependency Graph for each matrix entry.

The SBOM generation and dependency graph refresh jobs both run as matrix jobs. Each selected target is processed independently with its own `scan_label`, `source`, and `output_prefix`.

## Triggers

The workflow supports two entry points:

| Trigger | Purpose |
| --- | --- |
| `workflow_call` | Allows other workflows to reuse this workflow. |
| `workflow_dispatch` | Allows manual runs for testing or one-off refreshes. |

## Inputs

| Input | Required | Default | Description |
| --- | --- | --- | --- |
| `source_path` | No | `.` | Repository path or subdirectory to scan for ecosystem manifests. |
| `syft_version` | No | `v1.45.0` | Syft version used to generate deterministic SBOM output. |
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

If no scan targets are detected, the matrix jobs are skipped.

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

## Manual run

Use the `workflow_dispatch` trigger to run this workflow directly from the GitHub Actions UI. Override `source_path` to test a specific subdirectory without changing caller workflows.

## Notes

- SBOM generation is ecosystem-agnostic and uses Syft for both CycloneDX and SPDX output.
- The dependency graph refresh step runs in a matrix and submits each scan target with a distinct correlator.
- Matrix detection is handled before fan-out because GitHub Actions requires matrix values to be known before matrix jobs start.
