from __future__ import annotations

from datetime import date, datetime

from langchain_core.tools import tool
from packaging.version import Version, InvalidVersion

from ...models.remediation_plan import (
    ActionPlan,
    ActionType,
    AuditEntry,
    FixClass,
    FixPlan,
    PackageContext,
    PlanState,
    RemediationPlan,
)
from ...models.security_package_triage import SecurityPackageTriage
from ...tools.github_pr_collector.model.pull_request_metadata import PullRequestMetadata

from .utils.fix_classifier import FixClassifier


@tool("build_remediation_plan")
def build_remediation_plan(
    pkg: SecurityPackageTriage,
) -> RemediationPlan:
    """Build a remediation plan from a package vulnerability triage result."""
    if pkg.istransitive:
        return build_transitive_plan(pkg)
    return build_direct_plan(pkg)


def derive_fix_class(pkg: SecurityPackageTriage) -> FixClass:
    return FixClassifier.derive_fix_class(pkg)


def derive_action_type(
    pkg: SecurityPackageTriage,
    fix_class: FixClass,
) -> ActionType:
    return FixClassifier.derive_action_type(pkg, fix_class)


def build_direct_plan(pkg: SecurityPackageTriage) -> RemediationPlan:
    fix_class = derive_fix_class(pkg)
    action_type = derive_action_type(pkg, fix_class)
    severity = effective_severity(pkg)
    ghsas = dedupe_ghsas(pkg.vulnerabilities)

    return RemediationPlan(
        plan_id=f"plan_{pkg.package}_{pkg.ecosystem}_{date.today():%Y%m%d}",
        created_at=datetime.utcnow(),
        package=PackageContext(
            name=pkg.package,
            ecosystem=pkg.ecosystem,
            current_version_range=pkg.current_version_range,
            remediated_version=pkg.remediated_version,
            effective_severity=severity,
            relationship=FixClassifier.derive_relationship(pkg),
            transitive_source_package=pkg.transitive_source_package,
            unique_ghsas=ghsas,
        ),
        fix=FixPlan(
            fix_class=fix_class,
            non_breaking_fix=pkg.non_breaking_upgrade_version or None,
            breaking_fix=pkg.breaking_upgrade_version or None,
            upgrade_version=pkg.upgrade_version,
            partial_fix_available=bool(
                pkg.non_breaking_upgrade_version and pkg.breaking_upgrade_version
            ),
            patch_available=False,
        ),
        action=ActionPlan(
            action_type=action_type,
            pull_url=resolve_pull_url(pkg, fix_class),
            pr_number=resolve_pr_number(pkg, fix_class),
            placeholder_markdown=(
                build_placeholder_markdown(pkg, fix_class, severity, ghsas)
                if action_type == ActionType.PLACEHOLDER_PR
                else ""
            ),
            target_package=pkg.package,
        ),
        state=PlanState(
            issue_id=pkg.issue_metadata.get("id", ""),
            issue_url=pkg.issue_metadata.get("url", ""),
        ),
        audit=[
            AuditEntry(
                timestamp=datetime.utcnow().isoformat(),
                agent="remediation_planner",
                action="plan_created",
                detail=(
                    f"fix_class={fix_class.value}, "
                    f"action={action_type.value}, "
                    f"severity={severity}"
                ),
            )
        ],
    )


def build_transitive_plan(pkg: SecurityPackageTriage) -> RemediationPlan:
    """
    For transitive findings we cannot bump pkg itself — it is not declared in
    the project's manifest. The fix must come from bumping one of the direct
    dependencies that pulls pkg in (transitive_source_package).

    Decision tree
    ─────────────
    1. No source identified → open_issue (triage data incomplete).
    2. Source identified, adequate PR exists (bumps source to >= required fix)
       → point action at that PR (rollup_pr / standalone_pr).
    3. Source identified, PR exists but undershoots the required version
       → placeholder_pr targeting the source at the required version,
         with a note that the existing PR is insufficient.
    4. Source identified, no PR at all, but source has a known fix version
       → placeholder_pr targeting source@required_version.
    5. Source identified, no PR, no known fix for the source
       → open_issue with full transitive chain context.
    """
    severity = effective_severity(pkg)
    ghsas = dedupe_ghsas(pkg.vulnerabilities)

    if not pkg.transitive_source_package:
        action = ActionPlan(
            action_type=ActionType.OPEN_ISSUE,
            pull_url="",
            pr_number=None,
            placeholder_markdown="",
            target_package="UNKNOWN_SOURCE_PACKAGE",
        )
        return _finalize_transitive_plan(
            pkg, severity, ghsas, action,
            source_package="unidentified",
            source_required_version=None,
            undershooting_pr=None,
        )

    # BUG-1 + BUG-2 FIX: strip the "@version" suffix before comparing, and
    # only accept PRs whose bump target satisfies the required fix version.
    source_pr, source_package, source_required_version = find_source_pull_metadata(pkg)

    if source_pr is not None:
        # Case 2: found a PR that adequately covers the required version bump.
        action_type = (
            ActionType.ROLLUP_PR
            if len(source_pr.version_bumps) > 1
            else ActionType.STANDALONE_PR
        )
        action = ActionPlan(
            action_type=action_type,
            pull_url=source_pr.pull_url,
            pr_number=source_pr.pr_number,
            placeholder_markdown="",
            target_package=source_package,
        )
        return _finalize_transitive_plan(
            pkg, severity, ghsas, action,
            source_package=source_package,
            source_required_version=source_required_version,
            undershooting_pr=None,
        )

    # No adequate PR found. Check whether there is an *undershooting* PR
    # (exists but targets a version below what's needed) so we can note it.
    undershooting_pr, _ = find_undershooting_pr(pkg, source_package)

    if source_required_version:
        # Cases 3 & 4: we know what version the source needs to reach.
        # BUG-4 FIX: produce a placeholder_pr (not open_issue) so the
        # workflow generates a stub issue/PR tracking the source bump.
        action = ActionPlan(
            action_type=ActionType.PLACEHOLDER_PR,
            pull_url="",
            pr_number=None,
            placeholder_markdown=build_transitive_placeholder_markdown(
                pkg=pkg,
                severity=severity,
                ghsas=ghsas,
                source_package=source_package,
                source_required_version=source_required_version,
                undershooting_pr=undershooting_pr,
            ),
            target_package=source_package,
        )
    else:
        # Case 5: source package has no known fix version either.
        action = ActionPlan(
            action_type=ActionType.OPEN_ISSUE,
            pull_url="",
            pr_number=None,
            placeholder_markdown="",
            target_package=source_package,
        )

    return _finalize_transitive_plan(
        pkg, severity, ghsas, action,
        source_package=source_package,
        source_required_version=source_required_version,
        undershooting_pr=undershooting_pr,
    )


def _finalize_transitive_plan(
    pkg: SecurityPackageTriage,
    severity: str,
    ghsas: list[str],
    action: ActionPlan,
    source_package: str,
    source_required_version: str | None,
    undershooting_pr: PullRequestMetadata | None,
) -> RemediationPlan:
    # BUG-3 FIX: derive the real fix_class from whether the source package
    # has a known required version, instead of always hardcoding NO_FIX_AVAILABLE.
    # For transitive findings the "fix" is always expressed in terms of the
    # source package, so non_breaking_fix / breaking_fix hold the source version.
    if source_required_version:
        fix_class = FixClass.NON_BREAKING_BUMP
        non_breaking_fix: str | None = source_required_version
        breaking_fix: str | None = None
        upgrade_version = source_required_version
    else:
        fix_class = FixClass.NO_FIX_AVAILABLE
        non_breaking_fix = None
        breaking_fix = None
        upgrade_version = ""

    audit_detail = (
        f"transitive_via={source_package or 'unidentified'}, "
        f"action={action.action_type.value}, "
        f"severity={severity}"
    )
    if source_required_version:
        audit_detail += f", source_fix_version={source_required_version}"
    if undershooting_pr:
        audit_detail += f", undershooting_pr=#{undershooting_pr.pr_number}"

    return RemediationPlan(
        plan_id=f"plan_{pkg.package}_{pkg.ecosystem}_{date.today():%Y%m%d}",
        created_at=datetime.utcnow(),
        package=PackageContext(
            name=pkg.package,
            ecosystem=pkg.ecosystem,
            current_version_range=pkg.current_version_range,
            remediated_version=pkg.remediated_version,
            effective_severity=severity,
            relationship="transitive",
            transitive_source_package=pkg.transitive_source_package,
            unique_ghsas=ghsas,
        ),
        fix=FixPlan(
            fix_class=fix_class,
            non_breaking_fix=non_breaking_fix,
            breaking_fix=breaking_fix,
            upgrade_version=upgrade_version,
            partial_fix_available=False,
            patch_available=False,
        ),
        action=action,
        state=PlanState(
            issue_id=pkg.issue_metadata.get("id", ""),
            issue_url=pkg.issue_metadata.get("url", ""),
        ),
        audit=[
            AuditEntry(
                timestamp=datetime.utcnow().isoformat(),
                agent="remediation_planner",
                action="plan_created",
                detail=audit_detail,
            )
        ],
    )


def _strip_version_suffix(package_ref: str) -> str:
    """
    Strip a pinned version from a package reference.
    'axios@0.28.1'          → 'axios'
    '@vue/cli-service@4.5.19' → '@vue/cli-service'   (scoped npm package)
    'axios'                 → 'axios'  (no suffix, no-op)
    """
    # Scoped npm packages start with '@'; the version separator is the
    # *second* '@'. Split on '@' and reconstruct carefully.
    parts = package_ref.split("@")
    if package_ref.startswith("@"):
        # ['', 'scope/name', '1.2.3']  →  '@scope/name'
        return "@" + parts[1] if len(parts) >= 3 else package_ref
    # ['name', '1.2.3']  →  'name'
    return parts[0]


def _version_satisfies_minimum(version_str: str, minimum: str) -> bool:
    """Return True if version_str >= minimum (both must be parseable)."""
    try:
        return Version(version_str) >= Version(minimum)
    except InvalidVersion:
        return False


def find_source_pull_metadata(
    pkg: SecurityPackageTriage,
) -> tuple[PullRequestMetadata | None, str, str | None]:
    """
    Search pkg.pull_metadata for a PR that:
      (a) bumps one of pkg.transitive_source_package, AND
      (b) bumps it to a version >= the required fix version for that source
          (derived from pkg.non_breaking_upgrade_version /
           pkg.breaking_upgrade_version on the *source* triage — approximated
           here as pkg.remediated_version which the triage populates for the
           child, or pkg.non_breaking_upgrade_version if set).

    BUG-1 FIX: strip '@version' suffix from transitive_source_package entries
               before comparing to bump.package.
    BUG-2 FIX: reject PRs whose bump target undershoots the required version.

    Returns (matching_pr, source_package_name, required_version) or
            (None, first_source_name, required_version).
    The required_version is derived from pkg even when no PR matches, so the
    caller can still produce a placeholder_pr targeting that version.
    """
    sources = pkg.transitive_source_package or []

    # The required version to fix the *child* pkg is what the triage reports.
    # For a transitive finding, pkg.remediated_version is the child's fix
    # version (e.g. form-data >= 4.0.6), but what we need to bump is the
    # *source*. The source's required version is stored on the source's own
    # triage; we approximate it here using the pkg's upgrade fields which
    # reflect what version of the source closes the child advisory.
    required_version: str | None = (
        pkg.non_breaking_upgrade_version
        or pkg.breaking_upgrade_version
        or pkg.upgrade_version
        or pkg.remediated_version
        or None
    )

    for source in sources:
        source_name = _strip_version_suffix(source)   # BUG-1 FIX
        for pr in pkg.pull_metadata:
            for bump in pr.version_bumps:
                if bump.package.lower() != source_name.lower():
                    continue
                # BUG-2 FIX: check the PR actually reaches the required version.
                if required_version and not _version_satisfies_minimum(
                    bump.to_version, required_version
                ):
                    continue  # PR exists but undershoots — keep searching
                return pr, source_name, required_version

    return None, (_strip_version_suffix(sources[0]) if sources else ""), required_version


def find_undershooting_pr(
    pkg: SecurityPackageTriage,
    source_name: str,
) -> tuple[PullRequestMetadata | None, str]:
    """
    Return the first PR that bumps source_name but to an insufficient version.
    Used to surface the 'existing PR undershoots' note in placeholder markdown
    and issue titles.
    """
    for pr in pkg.pull_metadata:
        for bump in pr.version_bumps:
            if bump.package.lower() == source_name.lower():
                return pr, bump.to_version
    return None, ""


# ── AC line builder ───────────────────────────────────────────────────────────

def build_ac_line(
    *,
    target_package: str,
    current_version_range: str,
    target_version: str | None,
    breaking: bool,
    relationship: str,            # "direct" | "transitive"
    ghsas: list[str],
    dependency_paths: list[str] | None = None,
    pr_ref: str | None = None,    # e.g. "existing PR #123 insufficient (reaches `1.2.0`)"
) -> str:
    """
    Produce a parseable acceptance-criteria block summarizing exactly what
    needs to change. Designed to double as an LLM coding-agent prompt.
    """
    fixed_str = f">={target_version}" if target_version else "no known fix"
    dependency_paths = dependency_paths or []
    dependency_path_lines = "\n".join(
        f"- {dependency_path}" for dependency_path in dependency_paths
    ) or "- —"
    advisory_lines = "\n".join(f"- {ghsa}" for ghsa in ghsas) or "- —"
    pr_str = f"; {pr_ref}" if pr_ref else ""

    return (
        f"## {target_package}\n\n"
        f"Package: {target_package}\n"
        f"Type: {relationship}\n"
        f"Affected: {current_version_range}\n"
        f"Fixed: {fixed_str}\n"
        f"Is Breaking Dependency: {'Yes' if breaking else 'No'}{pr_str}\n"
        f"Dependency paths:\n"
        f"{dependency_path_lines}\n\n"
        f"Advisories:\n"
        f"{advisory_lines}"
    )


# ── Content builders ──────────────────────────────────────────────────────────

def build_transitive_placeholder_markdown(
    pkg: SecurityPackageTriage,
    severity: str,
    ghsas: list[str],
    source_package: str,
    source_required_version: str,
    undershooting_pr: PullRequestMetadata | None,
) -> str:
    """
    BUG-4 + BUG-5 FIX: produce a placeholder_pr markdown (not open_issue) when
    the source package has a known fix version, and include full transitive
    chain context — child package, affected version range, GHSAs, and a note
    about any existing PR that falls short.

    The body leads with a parseable AC block (built via build_ac_line()) that
    captures the full fix spec — package, affected/fixed versions, breaking
    flag, dependency paths, and every closed GHSA/CVE. The table below it is
    kept only as supplementary human-readable context.
    """
    sources_str = ", ".join(pkg.transitive_source_package)

    pr_ref = None
    if undershooting_pr:
        _, to_ver = find_undershooting_pr(pkg, source_package)
        pr_ref = f"existing PR #{undershooting_pr.pr_number} insufficient (reaches `{to_ver}`)"

    ac_line = build_ac_line(
        target_package=source_package,
        current_version_range=pkg.current_version_range,
        target_version=source_required_version,
        breaking=False,
        relationship="transitive",
        dependency_paths=pkg.transitive_source_package,
        ghsas=ghsas,
        pr_ref=pr_ref,
    )

    return f"""{ac_line}

### Issue details
| Field | Value |
|---|---|
| Vulnerable package | `{pkg.package}` |
| Ecosystem | `{pkg.ecosystem}` |
| Vulnerable range | `{pkg.current_version_range}` |
| Patched vulnerable package version | `{source_required_version}` |
| Relationship | `transitive` |
| GHSAs | {", ".join(ghsas) if ghsas else "—"} |

### Source details
| Field | Value |
|---|---|
| Source package to update | `{source_package}` |
| Source candidates from dependency graph | {sources_str or "—"} |
| Required source version | `{source_package} >= {source_required_version}` |

### Vulnerability summary
{build_vuln_summary_lines(pkg.vulnerabilities)}

### Resolution options
- [ ] Assign to coding agent (Copilot / LLM) to author the fix PR
- [ ] Self-resolve — bump `{source_package}` to `>= {source_required_version}` manually

### Notes
_Add context, blockers, or migration hints here._
"""

def resolve_pull_url(pkg: SecurityPackageTriage, fix_class: FixClass) -> str:
    if fix_class == FixClass.NON_BREAKING_BUMP and pkg.non_breaking_pull_metadata:
        return pkg.non_breaking_pull_metadata.pull_url
    if fix_class == FixClass.BREAKING_BUMP and pkg.breaking_pull_metadata:
        return pkg.breaking_pull_metadata.pull_url
    if fix_class == FixClass.PARTIAL_FIX_AVAILABLE:
        if pkg.non_breaking_pull_metadata:
            return pkg.non_breaking_pull_metadata.pull_url
        if pkg.breaking_pull_metadata:
            return pkg.breaking_pull_metadata.pull_url
    return ""


def resolve_pr_number(pkg: SecurityPackageTriage, fix_class: FixClass) -> int | None:
    if fix_class == FixClass.NON_BREAKING_BUMP and pkg.non_breaking_pull_metadata:
        return pkg.non_breaking_pull_metadata.pr_number
    if fix_class == FixClass.BREAKING_BUMP and pkg.breaking_pull_metadata:
        return pkg.breaking_pull_metadata.pr_number
    if fix_class == FixClass.PARTIAL_FIX_AVAILABLE:
        if pkg.non_breaking_pull_metadata:
            return pkg.non_breaking_pull_metadata.pr_number
        if pkg.breaking_pull_metadata:
            return pkg.breaking_pull_metadata.pr_number
    return None


def build_placeholder_markdown(
    pkg: SecurityPackageTriage,
    fix_class: FixClass,
    severity: str,
    ghsas: list[str],
) -> str:
    """
    Leads with a parseable AC block (built via build_ac_line()) capturing
    package, affected/fixed versions, breaking flag, dependency paths, and
    every closed GHSA/CVE. The table below is kept only as supplementary
    human-readable context.
    """
    breaking = fix_class in (FixClass.BREAKING_BUMP, FixClass.PARTIAL_FIX_AVAILABLE)
    target = (
        pkg.breaking_upgrade_version
        or pkg.non_breaking_upgrade_version
        or pkg.upgrade_version
        or pkg.remediated_version
    )

    ac_line = build_ac_line(
        target_package=pkg.package,
        current_version_range=pkg.current_version_range,
        target_version=target,
        breaking=breaking,
        relationship="direct",
        dependency_paths=[],
        ghsas=ghsas,
    )

    return f"""{ac_line}

**Target version:** {target or "—"}

| Field | Value |
|---|---|
| Ecosystem | `{pkg.ecosystem}` |
| Current range | `{pkg.current_version_range}` |
| Target version | `{target or "—"}` |
| Relationship | direct |
| Breaking change | {"Yes" if breaking else "No"} |
| GHSAs | {", ".join(ghsas) if ghsas else "—"} |

### Vulnerability summary
{build_vuln_summary_lines(pkg.vulnerabilities)}

### Resolution options
- [ ] Assign to coding agent (Copilot / LLM) to author the fix PR
- [ ] Self-resolve — implement migration manually

### Notes
_Add context, blockers, or migration hints here._
"""

# ── Utilities ─────────────────────────────────────────────────────────────────

def effective_severity(pkg: SecurityPackageTriage) -> str:
    return pkg.severity


def dedupe_ghsas(vulnerabilities: list) -> list[str]:
    seen, output = set(), []
    for vulnerability in vulnerabilities:
        if vulnerability.ghsa_id not in seen:
            seen.add(vulnerability.ghsa_id)
            output.append(vulnerability.ghsa_id)
    return output


def build_vuln_summary(vulnerabilities: list) -> str:
    unique = {vulnerability.ghsa_id: vulnerability for vulnerability in vulnerabilities}
    return "; ".join(vulnerability.summary for vulnerability in unique.values())


def build_vuln_summary_lines(vulnerabilities: list) -> str:
    unique = {vulnerability.ghsa_id: vulnerability for vulnerability in vulnerabilities}
    return "\n".join(
        f"- **{vulnerability.ghsa_id}** (CVSS {vulnerability.cvss}) — {vulnerability.summary}"
        for vulnerability in unique.values()
    )
