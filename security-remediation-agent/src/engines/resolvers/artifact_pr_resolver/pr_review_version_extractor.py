import logging
from contextlib import nullcontext
from typing import Any

import httpx

from ....models.gh.pull_request_metadata import VersionBump
from ....tools.utils.github_api import (
    GITHUB_API_TIMEOUT,
    GitHubApiError,
    get_github_headers,
)

logger = logging.getLogger(__name__)


def _get(client: httpx.Client, url: str) -> Any:
    """Fetch JSON without turning transport or response failures into empty results."""
    try:
        response = client.get(url)
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        logger.error("GitHub dependency review returned HTTP %d", exc.response.status_code)
        raise GitHubApiError(
            f"GitHub dependency review failed with HTTP {exc.response.status_code}",
            status_code=exc.response.status_code,
        ) from exc
    except httpx.HTTPError as exc:
        logger.exception("GitHub dependency review request failed")
        raise GitHubApiError("GitHub dependency review request failed") from exc

    try:
        return response.json()
    except ValueError as exc:
        logger.exception("GitHub dependency review returned invalid JSON")
        raise GitHubApiError("GitHub dependency review returned invalid JSON") from exc


def _extract_bumps(changes: Any) -> list[VersionBump]:
    if not isinstance(changes, list):
        logger.error("GitHub dependency comparison did not return a list")
        raise GitHubApiError("GitHub dependency comparison did not return a list")

    grouped: dict[tuple[str, str, str], dict[str, set[str]]] = {}
    for change in changes:
        if (
            not isinstance(change, dict)
            or any(
                not isinstance(change.get(field), str) or not change[field].strip()
                for field in ("manifest", "ecosystem", "name", "version")
            )
            or change.get("change_type") not in ("removed", "added")
        ):
            logger.error("GitHub dependency comparison returned an invalid change record")
            raise GitHubApiError("GitHub dependency comparison returned an invalid change record")

        key = (change["manifest"], change["ecosystem"], change["name"])
        versions = grouped.setdefault(key, {"removed": set(), "added": set()})
        versions[change["change_type"]].add(change["version"])

    bumps: list[VersionBump] = []
    seen: set[tuple[str, str, str]] = set()
    for (manifest, ecosystem, name), versions in grouped.items():
        old, new = versions["removed"], versions["added"]
        # Additions and removals alone do not establish a version transition.
        if not old or not new:
            continue
        # The API exposes sets of changes, not edges connecting old/new versions.
        # Never zip sorted sets: doing so can invent a remediation transition.
        if len(old) != 1 or len(new) != 1:
            logger.error(
                "Ambiguous version change for %s (%s) in %s: %d removed, %d added",
                name, ecosystem, manifest, len(old), len(new),
            )
            raise GitHubApiError(
                f"Ambiguous version change for {name} ({ecosystem}) in {manifest}"
            )

        from_version, to_version = next(iter(old)), next(iter(new))
        if from_version == to_version:
            continue
        key = (name, from_version, to_version)
        if key not in seen:
            seen.add(key)
            bumps.append(
                VersionBump(
                    package=name, from_version=from_version, to_version=to_version,
                )
            )
    return bumps


def extract_version_changes(owner: str, repo: str, pr_number: int, *,
                            pull_request: dict | None = None, client: httpx.Client | None = None) -> list[VersionBump]:
    """Return unambiguous dependency-review transitions using the shared PR model.

    Raises GitHubApiError for API failures, malformed responses, or ambiguous
    version pairings. Dependencies only added or removed are not version bumps.
    """
    logger.info("Extracting dependency-review version changes for %s/%s#%d", owner, repo, pr_number)
    base_url = f"https://api.github.com/repos/{owner}/{repo}"
    session = nullcontext(client) if client is not None else httpx.Client(
        headers=get_github_headers(), timeout=GITHUB_API_TIMEOUT)
    with session as client:
        pr = pull_request
        if not isinstance(pr, dict) or any(
            not isinstance(pr.get(ref), dict) or not pr[ref].get("sha") for ref in ("base", "head")
        ):
            pr = _get(client, f"{base_url}/pulls/{pr_number}")
        if not isinstance(pr, dict) or any(
            not isinstance(pr.get(ref), dict)
            or not isinstance(pr[ref].get("sha"), str)
            or not pr[ref]["sha"].strip()
            for ref in ("base", "head")
        ):
            logger.error("GitHub pull request response is missing base/head commit SHAs")
            raise GitHubApiError("GitHub pull request response is missing base/head commit SHAs")

        base_sha, head_sha = pr["base"]["sha"], pr["head"]["sha"]
        changes = _get(client, f"{base_url}/dependency-graph/compare/{base_sha}...{head_sha}")

    bumps = _extract_bumps(changes)
    logger.info(
        "Extracted %d dependency-review version bump(s) for %s/%s#%d",
        len(bumps), owner, repo, pr_number,
    )
    return bumps
