import re

from pydantic import BaseModel


class VersionBump(BaseModel):
    package: str
    from_version: str
    to_version: str


def extract_from_title(title: str) -> list[VersionBump]:
    """Try to pull a single package update out of the PR title."""
    title = title or ""
    results = []

    # Dependabot:
    # Bump python-jose from 3.3.0 to 3.4.0
    m = re.search(
        r"^[Bb]umps?\s+(\S+)\s+from\s+(\S+)\s+to\s+(\S+)",
        title,
    )
    if m:
        results.append(
            VersionBump(
                package=m.group(1),
                from_version=m.group(2),
                to_version=m.group(3),
            )
        )
        return results

    # Renovate:
    # chore(deps): update dependency requests to v2.31.0
    m = re.search(
        r"(?:update|bump)(?:\s+dependency)?\s+(\S+)\s+to\s+v?(\S+)",
        title,
        re.IGNORECASE,
    )
    if m:
        results.append(
            VersionBump(
                package=m.group(1),
                from_version="",
                to_version=m.group(2),
            )
        )

    return results

def _clean_version(version: str) -> str:
    """
    Strip semver range-operator prefixes (^, ~, >=, <=, >, <, =) and
    surrounding whitespace from a version string.
 
    Renovate table cells often render the *range* rather than the bare
    version, e.g. "^0.31.0" or "~> 1.2.3". Without stripping this, the
    extracted to_version/from_version will never exactly equal a bare
    version string computed elsewhere (e.g. "0.31.0" from an advisory's
    first_patched field), causing downstream exact-match comparisons to
    silently fail even though the versions are equivalent.
    """
    return version.lstrip("^~>=< ").strip()

# Dependabot grouped-update table row, e.g.:
#   | [axios](url) | 0.28.1 | 1.18.1 |
#   | underscore   | 1.13.6 | 1.13.8 |
#
# Unlike the Renovate table below, grouped Dependabot PRs (raised via a
# `groups:` block in dependabot.yml) render a plain 3-column table with no
# backticks and no "->" arrow between versions — each version sits in its
# own cell instead. Without a dedicated matcher, every package in a grouped
# PR body silently produces zero VersionBump entries, which empties
# version_bumps for the whole PR and drops every one of its packages out of
# rollup/standalone matching into placeholder, even though the PR already
# fixes them.
_GROUPED_TABLE_ROW = re.compile(
    r"^\|\s*\[?`?([\w@/.\-]+)`?\]?(?:\([^)]*\))?\s*\|\s*"
    r"([0-9][0-9A-Za-z._+-]*)\s*\|\s*"
    r"([0-9][0-9A-Za-z._+-]*)\s*\|"
)

def extract_from_body(body: str) -> list[VersionBump]:
    """Pull all package updates out of the PR body."""
    body = body or ""
 
    results = []
    seen = set()
 
    def add(pkg, old, new):
        old = _clean_version(old)
        new = _clean_version(new)
        key = (pkg, old, new)
        if pkg and key not in seen:
            seen.add(key)
            results.append(
                VersionBump(
                    package=pkg,
                    from_version=old,
                    to_version=new,
                )
            )
 
    # Dependabot
    pattern = (
        r"(?:Bumps?|Updates?)\s+"
        r"\[?`?([^\]`\s]+)`?\]?"
        r"(?:\([^)]*\))?\s+"
        r"from\s+`?([0-9A-Za-z._+-]+)`?\s+"
        r"to\s+`?([0-9A-Za-z._+-]+)`?"
    )
 
    for m in re.finditer(pattern, body, re.IGNORECASE):
        add(
            m.group(1),
            m.group(2),
            m.group(3),
        )
 
    # Renovate markdown table
    for line in body.splitlines():
        if "->" not in line or "|" not in line:
            continue
 
        pkg_match = re.match(
            r"\s*\|\s*\[?`?([\w@/.\-]+)`?\]?(?:\([^)]*\))?\s*\|",
            line,
        )
 
        ver_match = re.search(
            r"`([^`]+)`\s*->\s*`([^`]+)`",
            line,
        )
 
        if pkg_match and ver_match:
            add(
                pkg_match.group(1),
                ver_match.group(1),
                ver_match.group(2),
            )

    # Dependabot grouped-update table (plain 3-column, no arrow/backticks).
    # Runs as its own pass over lines the Renovate-table loop above didn't
    # already claim (those contain "->" and are handled there), so a single
    # line is never double-counted between the two table matchers.
    for line in body.splitlines():
        if "->" in line or "|" not in line:
            continue

        m = _GROUPED_TABLE_ROW.match(line.strip())
        if m:
            add(
                m.group(1),
                m.group(2),
                m.group(3),
            )
 
    # Generic fallback
    if not results:
        for m in re.finditer(
            r"([\w@/.\-]+)\s+from\s+`?([0-9A-Za-z._+-]+)`?\s+to\s+`?([0-9A-Za-z._+-]+)`?",
            body,
            re.IGNORECASE,
        ):
            add(
                m.group(1),
                m.group(2),
                m.group(3),
            )
 
    return results


def get_version_bumps(title: str, body: str) -> list[VersionBump]:
    updates = extract_from_body(body)
    if not updates:
        updates = extract_from_title(title)

    return updates