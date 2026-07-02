# GitHub Actions workflows

## OSV Scanner reusable workflow

The `osv-scanner.yml` workflow runs [OSV Scanner](https://google.github.io/osv-scanner/) as a reusable GitHub Actions workflow. It checks the calling repository for known vulnerabilities in dependency manifests, lockfiles, and vendored dependencies supported by OSV Scanner, writes the results as SARIF, and uploads them to GitHub code scanning.

### Workflow file

`.github/workflows/osv-scanner.yml`

### Trigger

This workflow is triggered with `workflow_call`, so it is intended to be called from another workflow rather than run directly.

### Permissions

The workflow uses:

| Permission | Purpose |
| --- | --- |
| `contents: read` | Checks out repository contents for scanning. |
| `security-events: write` | Allows scanner results to be uploaded to GitHub code scanning. |

### Inputs

| Input | Required | Default | Description |
| --- | --- | --- | --- |
| `scan-args` | No | `-r --skip-git --format=sarif --output=osv-scanner-results.sarif ./` | Arguments passed to OSV Scanner. |

The default arguments scan the repository recursively, skip Git metadata, write SARIF results to `osv-scanner-results.sarif`, and scan from the repository root.

### Example usage

Create a workflow in the calling repository, such as `.github/workflows/security-scan.yml`:

```yaml
name: Security scan

on:
  pull_request:
  push:
    branches:
      - main
  workflow_dispatch:

jobs:
  osv-scan:
    uses: ./.github/workflows/osv-scanner.yml
```

To override the scanner arguments:

```yaml
jobs:
  osv-scan:
    uses: ./.github/workflows/osv-scanner.yml
    with:
      scan-args: |
        -r
        --skip-git
        --format=sarif
        --output=osv-scanner-results.sarif
        ./src
```

Keep `--format=sarif` and `--output=osv-scanner-results.sarif` in custom `scan-args` if you want vulnerability results uploaded to GitHub code scanning.

### Notes

- The workflow runs on `ubuntu-latest`.
- It checks out the repository with `actions/checkout@v4`.
- It runs `google/osv-scanner-action/osv-scanner-action@v1.7.1`.
- It uploads `osv-scanner-results.sarif` with `github/codeql-action/upload-sarif@v3` when the SARIF file exists.
