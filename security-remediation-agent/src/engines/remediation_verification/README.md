# Remediation verification

The pipeline runs triage, compatibility review, Renovate grouping, verification, then reporting.
The verification agent groups recommendations by declaration manifest across all bundles.
It stages the original manifest and available lockfile in a temporary directory using the repository ref.
The checkout is never changed.

## Candidate selection

Recommendations for the same normalized package share one resolver pin. The candidate must be
present in every recommendation's qualifying list. The lowest common candidate is tried first;
when it fails, a shared compatible candidate may be retried. Fallback candidates are resolved
with previously accepted upgrades. Recommendations without a common candidate remain unresolved.
Every returned version belongs to a set that resolved together.

The agent assigns `verified_version` from the final result. Candidates retain `isVerified`,
`verification_status` (`SUCCESS` or `FAILED`), and diagnostic messages.

## Engines

- npm resolves the original manifest first with `npm install --package-lock-only --ignore-scripts
  --no-audit --no-fund --legacy-peer-deps=false`. Repository-root and project `.npmrc`
  `legacy-peer-deps=true` settings select legacy mode immediately. Only a baseline `ERESOLVE`
  failure triggers an automatic legacy retry. Candidate attempts use the same flags as the baseline.
  Legacy mode is disclosed in triage notes because it does not check peer compatibility.
  A failed baseline stops candidate attempts and produces one detailed manifest note.
  Successful npm exit is the verification criterion; the lockfile graph is not inspected.
- Python requirements and PEP 621 projects use `uv pip compile` with joint exact constraints
  and `--only-binary :all:`. Selected requirement pins replace their original specifiers;
  other requirements remain constraints. The resolved output must contain the selected versions.
- NuGet project files use `dotnet restore`, with NU1605 and NU1608 treated as errors.
  The engine verifies selected versions in `obj/project.assets.json`. Central package management
  without inline versions is unsupported.

Snapshots currently contain only the selected manifest and lockfile. Workspace siblings, local
path dependencies, shared build properties and private registry settings are not staged.
Yarn/pnpm-native projects, native Poetry and uv workspaces are unsupported by these engines.

## Execution limits

Each subprocess has a maximum five-minute timeout, bounded by the remaining fifteen-minute
manifest budget. Worker copies isolate candidate mutations until completion, so a timed-out
worker cannot overwrite published results. The deadline prevents further resolver attempts.

Resolution may access registries and download metadata or binary distributions. It does not run
project builds or tests and does not establish runtime readiness or an independent security scan.
Verification reflects the resolver's current platform and runtime, rather than every deployment target.
