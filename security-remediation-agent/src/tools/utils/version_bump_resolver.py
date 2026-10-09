import logging
import re

from pydantic import BaseModel

logger = logging.getLogger(__name__)


class VersionBump(BaseModel):
    package: str
    from_version: str
    to_version: str

    def __eq__(self, other: object) -> bool:
        if isinstance(other, dict):
            return self.model_dump() == other

        if isinstance(other, VersionBump):
            return self.model_dump() == other.model_dump()

        return super().__eq__(other)

    def __iter__(self):
        yield from self.model_dump().items()


def _clean_version(version: str) -> str:
    """
    Normalize a version extracted from PR text.

    Examples:
        ^1.2.3    -> 1.2.3
        v1.2.3    -> 1.2.3
        >=1.2.3   -> 1.2.3
        4.28.9.   -> 4.28.9
        `8.5.28`  -> 8.5.28
    """
    version = (version or "").strip()

    # Remove markdown/backticks/quotes.
    version = version.strip("`'\"")

    # Remove common version/range prefixes.
    version = version.lstrip("vV^~>=< ")

    # Remove punctuation accidentally captured from prose.
    version = version.rstrip(".,;:)")

    return version.strip()


def _strip_markdown_text(value: str) -> str:
    """
    Remove simple markdown formatting from a package name.

    Examples:
        [axios](https://...) -> axios
        `postcss`            -> postcss
        **vue**              -> vue
    """
    value = value or ""

    # Markdown link: [text](url) -> text
    value = re.sub(
        r"\[([^\]]+)\]\([^)]*\)",
        r"\1",
        value,
    )

    value = value.replace("`", "")
    value = value.replace("*", "")
    value = value.strip()

    # Remove trailing "(...)" metadata.
    value = re.sub(
        r"\s+\([^)]*\)$",
        "",
        value,
    )

    value = value.replace("(source)", "")
    value = value.replace("(source )", "")

    return value.strip()


def _add_version_bump(
    results: list[VersionBump],
    seen: set[tuple[str, str, str]],
    pkg: str,
    old: str,
    new: str,
) -> None:
    """
    Normalize, deduplicate, and add a version bump.
    """
    pkg = _strip_markdown_text(pkg)
    old = _clean_version(old)
    new = _clean_version(new)

    if not pkg or not old or not new:
        return

    # Normalize package case only for duplicate detection.
    key = (
        pkg.lower(),
        old,
        new,
    )

    if key in seen:
        return

    seen.add(key)

    results.append(
        VersionBump(
            package=pkg,
            from_version=old,
            to_version=new,
        )
    )


def _extract_dependabot_body(body: str) -> list[VersionBump]:
    """
    Extract dependency updates from a Dependabot PR body.

    Supports:
      - Bumps axios from 0.28.1 to 1.20.0
      - Updates `postcss` from `8.4.39` to `8.5.28`
      - Dependabot grouped markdown tables
      - Generic "package from X to Y" fallback
    """
    body = body or ""

    results: list[VersionBump] = []
    seen: set[tuple[str, str, str]] = set()

    #
    # 1. Standard Dependabot text
    #
    # Examples:
    #
    # Bumps axios from 0.28.1 to 1.20.0
    #
    # Updates `postcss` from `8.4.39` to `8.5.28`.
    #
    # Bumps [axios](https://github.com/axios/axios)
    # from 0.28.1 to 1.20.0
    #
    standard_pattern = re.compile(
        r"(?:Bumps?|Updates?)\s+"
        r"(?:\[)?"
        r"`?([\w@/.\-]+)`?"
        r"(?:\])?"
        r"(?:\([^)]*\))?"
        r"\s+"
        r"from\s+"
        r"`?([0-9][0-9A-Za-z._+-]*)`?"
        r"\s+"
        r"to\s+"
        r"`?([0-9][0-9A-Za-z._+-]*)`?",
        re.IGNORECASE,
    )

    for match in standard_pattern.finditer(body):
        _add_version_bump(
            results,
            seen,
            match.group(1),
            match.group(2),
            match.group(3),
        )

    #
    # 2. Dependabot grouped markdown table
    #
    # Examples:
    #
    # | axios | 0.28.1 | 1.20.0 |
    # | postcss | 8.4.39 | 8.5.28 |
    #
    # Leading/trailing pipes are optional.
    #
    grouped_pattern = re.compile(
        r"^\|?\s*"
        r"(?:\[)?"
        r"`?([\w@/.\-]+)`?"
        r"(?:\])?"
        r"(?:\([^)]*\))?"
        r"\s*\|\s*"
        r"`?([0-9][0-9A-Za-z._+-]*)`?"
        r"\s*\|\s*"
        r"`?([0-9][0-9A-Za-z._+-]*)`?"
        r"\s*\|?$",
        re.IGNORECASE,
    )

    for line in body.splitlines():
        row = line.strip()

        if "|" not in row:
            continue

        # Avoid alternate arrow-based table layouts here.
        if "->" in row or "→" in row:
            continue

        match = grouped_pattern.match(row)

        if match:
            _add_version_bump(
                results,
                seen,
                match.group(1),
                match.group(2),
                match.group(3),
            )

    #
    # 3. Generic fallback
    #
    # Example:
    #
    # axios from 0.28.1 to 1.20.0
    #
    # Versions must begin with a number. This prevents false positives
    # such as:
    #
    # changed from BSD-3-Clause to MIT
    # usage from toFormData to avoid
    #
    generic_pattern = re.compile(
        r"([\w@/.\-]+)\s+"
        r"from\s+"
        r"`?([0-9][0-9A-Za-z._+-]*)`?"
        r"\s+"
        r"to\s+"
        r"`?([0-9][0-9A-Za-z._+-]*)`?",
        re.IGNORECASE,
    )

    for match in generic_pattern.finditer(body):
        _add_version_bump(
            results,
            seen,
            match.group(1),
            match.group(2),
            match.group(3),
        )

    return results


def _extract_renovate_body(body: str) -> list[VersionBump]:
    """
    Extract package updates from Renovate markdown tables.

    Example:

        | Package | Type | Update | Change |
        |---|---|---|---|
        | axios | dependencies | major | 0.28.1 -> 1.20.0 |
    """
    body = body or ""

    results: list[VersionBump] = []
    seen: set[tuple[str, str, str]] = set()

    for line in body.splitlines():
        row = line.strip()

        if not row.startswith("|"):
            continue

        # Ignore markdown separator rows:
        # |---|---|---|
        if re.match(
            r"^\|?\s*[-:]+\s*(?:\|\s*[-:]+\s*)+\|?$",
            row,
        ):
            continue

        columns = [
            part.strip()
            for part in row.strip("|").split("|")
        ]

        if len(columns) < 2:
            continue

        package_cell = columns[0]

        if package_cell.lower() in {
            "package",
            "dependency",
            "name",
            "---",
        }:
            continue

        package = _strip_markdown_text(package_cell)

        if not package:
            continue

        # Find the column containing:
        # 1.2.3 -> 1.3.0
        # or
        # 1.2.3 → 1.3.0
        change_cell = next(
            (
                cell
                for cell in columns[1:]
                if "→" in cell or "->" in cell
            ),
            "",
        )

        if not change_cell:
            continue

        version_match = re.search(
            r"`?([vV^~>=<]*[0-9][0-9A-Za-z._+-]*)`?"
            r"\s*(?:->|→)\s*"
            r"`?([vV^~>=<]*[0-9][0-9A-Za-z._+-]*)`?",
            change_cell,
        )

        if not version_match:
            continue

        _add_version_bump(
            results,
            seen,
            package,
            version_match.group(1),
            version_match.group(2),
        )

    return results


def extract_from_body(
    category: str,
    body: str,
) -> list[VersionBump]:
    """
    Extract package updates using the parser matching the PR updater.
    """
    category = (category or "").lower()

    if category == "dependabot":
        return _extract_dependabot_body(body)

    if category == "renovatebot":
        return _extract_renovate_body(body)

    return []


def extract_from_title(
    title: str,
) -> list[VersionBump]:
    """
    Fallback extraction from the PR title.

    Examples:
        Bump axios from 0.28.1 to 1.20.0
        Update vue from 2.7.8 to 2.7.16
        Upgrade @vue/cli-service from 4.5.19 to 5.0.9
    """
    title = title or ""

    results: list[VersionBump] = []
    seen: set[tuple[str, str, str]] = set()

    pattern = re.compile(
        r"\b(?:bump|update|upgrade)\s+"
        r"([\w@/.:\-]+)\s+"
        r"from\s+"
        r"([vV^~>=<]*[0-9][0-9A-Za-z._+-]*)\s+"
        r"to\s+"
        r"([vV^~>=<]*[0-9][0-9A-Za-z._+-]*)",
        re.IGNORECASE,
    )

    for match in pattern.finditer(title):
        _add_version_bump(
            results,
            seen,
            match.group(1),
            match.group(2),
            match.group(3),
        )

    return results


def get_version_bumps(
    user: str,
    title: str,
    body: str,
) -> list[VersionBump]:
    """
    Return version bumps from a Dependabot or Renovate PR.

    Body extraction is preferred.
    If no updates are found in the body, fall back to the PR title.
    """
    user = user or ""

    normalized_user = user.lower()

    if "dependabot" in normalized_user:
        category = "dependabot"
    elif "renovate" in normalized_user:
        category = "renovatebot"
    else:
        category = "unknown"

    bumps = extract_from_body(
        category,
        body,
    )


    if bumps:
        return bumps

    logger.debug("No version bumps found in PR body; falling back to PR title")

    return extract_from_title(title)