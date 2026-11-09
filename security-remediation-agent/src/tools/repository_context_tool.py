import logging

import httpx

from ..models.security_remediation_context import RepositoryContext
from .utils.github_api import (
    GITHUB_API_TIMEOUT,
    GitHubApiError,
    _auth_hint,
    get_github_headers,
)

logger = logging.getLogger(__name__)

GITHUB_REPOS_URL = "https://api.github.com/repos"


async def _get(client: httpx.AsyncClient, url: str, resource: str, **params) -> httpx.Response:
    try:
        return await client.get(url, params=params or None)
    except httpx.HTTPError as exc:
        raise GitHubApiError(f"GitHub request for {resource} failed") from exc


async def _is_dependabot_enabled(client: httpx.AsyncClient, base_url: str) -> bool:
    """204 means dependabot alerts are enabled; 404 means disabled."""
    response = await _get(client, f"{base_url}/vulnerability-alerts", "Dependabot status")
    if response.status_code == 204:
        return True
    if response.status_code != 404:
        logger.warning("Dependabot health check returned HTTP %d%s",
                       response.status_code, _auth_hint(response.status_code))
    return False


async def _is_code_scanning_enabled(client: httpx.AsyncClient, base_url: str) -> bool:
    """Code scanning is enabled when its alerts endpoint answers 200.

    404 (no analysis found) and 403 (feature disabled) both mean it is off.
    """
    response = await _get(client, f"{base_url}/code-scanning/alerts", "code-scanning status", per_page=1)
    if response.status_code == 200:
        return True
    if response.status_code not in (403, 404):
        logger.warning("Code-scanning health check returned HTTP %d%s",
                       response.status_code, _auth_hint(response.status_code))
    return False


async def get_repository_context(owner: str, repo: str, ref: str | None = None) -> RepositoryContext:
    """Build a RepositoryContext from GitHub repository metadata and security feature health checks.

    ``ref`` overrides the repository's default branch when given.
    """
    base_url = f"{GITHUB_REPOS_URL}/{owner}/{repo}"
    async with httpx.AsyncClient(headers=get_github_headers(), timeout=GITHUB_API_TIMEOUT) as client:
        response = await _get(client, base_url, "repository")
        if response.status_code != 200:
            raise GitHubApiError(
                f"GitHub request for repository failed with HTTP {response.status_code}"
                f"{_auth_hint(response.status_code)}",
                status_code=response.status_code,
            )
        try:
            data = response.json()
        except ValueError as exc:
            raise GitHubApiError("GitHub returned invalid JSON for repository") from exc

        dependabot_enabled = await _is_dependabot_enabled(client, base_url)
        code_scanning_enabled = await _is_code_scanning_enabled(client, base_url)

    context = RepositoryContext(
        owner=(data.get("owner") or {}).get("login") or owner,
        repo=data.get("name") or repo,
        description=data.get("description") or "",
        ref=ref or data.get("default_branch") or "main",
        isPrivate=bool(data.get("private")),
        dependabotEnabled=dependabot_enabled,
        codeScanningEnabled=code_scanning_enabled,
    )
    logger.info("Repository context for %s/%s: private=%s dependabot=%s code_scanning=%s",
                context.owner, context.repo, context.isPrivate,
                context.dependabotEnabled, context.codeScanningEnabled)
    return context
