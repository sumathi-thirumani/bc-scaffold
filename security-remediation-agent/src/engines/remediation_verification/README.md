# Remediation verification

`RemediationVerificationAgent` runs after compatible-version collection in the review phase.
The factory chooses an engine from `upgrade_verifier.py`. Engines operate on a disposable
repository metadata snapshot pinned to the pipeline reference. They never modify the checkout.

Recommendations must have a stable, newer, same-major compatible candidate between their
minimum patched and highest stable versions. The candidate must also appear in the qualifying
upgrade evidence. Breaking fixes are deferred; unknown or contradictory evidence remains unresolved.

All accepted upgrades sharing a project are resolved together, including recommendations from
separate Renovate bundles. npm workspaces share their workspace root. Conflicting duplicate
recommendations reject the complete proposed set. Verified versions are published only after
resolution succeeds and the generated graph contains every requested exact candidate.

## Engines

- npm: exact declaration pins followed by `npm install --package-lock-only --ignore-scripts
  --no-audit --no-fund`; requires npm v2/v3 lock data and supports npm workspaces.
- Python requirements and PEP 621 projects: `uv pip compile` with a single joint constraint file,
  `--no-build --only-binary :all:`. Original declarations remain constraints, so incompatible
  candidates are rejected. The runner needs uv on PATH.
- Native Poetry, uv workspaces, Yarn, and NuGet verification are explicitly unsupported.
  Candidate collection for those ecosystems is independent of verification.

Resolution may use the network and download metadata or binary distributions. It does not install
project dependencies or run project builds/tests. Verification is for the resolver's current
platform and Python version, not every deployment target. Missing executables, missing inputs,
conflicts, unsupported formats, and failures leave verified_version unset.

Status and method are stored on each PackageUpgradeRecommendation. A successful result is
`resolution_verified` with method `dependency_resolution`, never a claim of runtime readiness
or an independent advisory/security scan. No-install resolution alone cannot establish either.
