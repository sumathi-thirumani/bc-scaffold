"""Run configuration for the security remediation agent.

Values come from CLI arguments first, then environment variables (the names a
GitHub Actions workflow passes), then defaults:

    SECURITY_REMEDIATION_ECOSYSTEMS            comma-separated or "All", default: all supported
                                               (unknown names are logged and skipped)
    SECURITY_REMEDIATION_VERIFICATION_ENABLED  true/false, default: true
    SECURITY_REMEDIATION_ADDITIONAL_UPDATES    true/false, default: false (also plan non-vulnerable
                                               updates found by the compatible-version review)
    SECURITY_REMEDIATION_ARTIFACT_OUTPUT       true/false, default: true (write remediation-plan.json
                                               and renovate.json5)
    GITHUB_TOKEN                               required; never read from a file
    GITHUB_REPOSITORY                          "owner/name", set automatically by Actions
"""

import logging
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from urllib.parse import urlparse

from ..models.security_remediation_constants import SecurityRemediationConstants

logger = logging.getLogger(__name__)

ECOSYSTEMS_ENV = "SECURITY_REMEDIATION_ECOSYSTEMS"
VERIFICATION_ENV = "SECURITY_REMEDIATION_VERIFICATION_ENABLED"
TOKEN_ENV = "GITHUB_TOKEN"
ADDITIONAL_UPDATES_ENV = "SECURITY_REMEDIATION_ADDITIONAL_UPDATES"
ARTIFACT_OUTPUT_ENV = "SECURITY_REMEDIATION_ARTIFACT_OUTPUT"
REPOSITORY_ENV = "GITHUB_REPOSITORY"

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}


class ConfigError(ValueError):
    """A required run setting is missing or cannot be interpreted."""
    pass


def normalize_repo_name(repo: str) -> str:
    """Accept a bare name, ``owner/name`` or a full GitHub URL and return the name."""
    value = repo.strip().strip("/")
    parsed = urlparse(value)
    if parsed.scheme in {"http", "https"} and parsed.path:
        parts = [part for part in parsed.path.strip("/").split("/") if part]
        if parts:
            return parts[-1].removesuffix(".git")
    return value.rsplit("/", 1)[-1].removesuffix(".git")


def parse_bool(value: str | bool | None, default: bool, name: str) -> bool:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    lowered = value.strip().lower()
    if lowered in _TRUE:
        return True
    if lowered in _FALSE:
        return False
    raise ConfigError(f"{name} must be true or false, got {value!r}")


def parse_ecosystems(value: str | list[str] | None) -> frozenset[str]:
    supported = SecurityRemediationConstants.SUPPORTED_ECOSYSTEMS
    if value is None or value == "" or value == []:
        return supported
    items = value.split(",") if isinstance(value, str) else value
    requested = {item.strip().lower() for item in items if item.strip()}
    if not requested or "all" in requested:
        return supported
    # Language-level names expand to every package-manager ecosystem behind them (pip covers uv/poetry manifests)
    for alias, members in SecurityRemediationConstants.ECOSYSTEM_GROUPS.items():
        if alias in requested:
            requested = (requested - {alias}) | members
    for name in sorted(requested - supported):
        logger.warning("Ecosystem %r was not found and is skipped; supported: %s", name, ", ".join(sorted(supported)))
    ecosystems = frozenset(requested & supported)
    if not ecosystems:
        logger.warning("No supported ecosystem selected; proceeding with all supported ecosystems")
        return supported
    return ecosystems


@dataclass(frozen=True)
class SecurityRemediationConfig:
    """Resolve one immutable configuration for a remediation run.

    Core idea: explicit CLI values override environment settings, then defaults apply.
    Validate repository and ecosystem inputs once, keep tokens out of repr output,
    and pass the optional branch or tag through the repository coordinates."""
    owner: str
    repo: str
    github_token: str = field(repr=False)
    ecosystems: frozenset[str] = SecurityRemediationConstants.SUPPORTED_ECOSYSTEMS
    verification_enabled: bool = True
    additional_updates: bool = False
    artifact_output: bool = True
    ref: str | None = None

    @property
    def repository(self) -> dict[str, str]:
        repo = {"owner": self.owner, "name": self.repo}
        if self.ref:
            repo["ref"] = self.ref
        return repo

    @classmethod
    def load(
        cls,
        *,
        owner: str | None = None,
        repo: str | None = None,
        ecosystems: str | list[str] | None = None,
        verification_enabled: bool | str | None = None,
        additional_updates: bool | str | None = None,
        artifact_output: bool | str | None = None,
        ref: str | None = None,
        env: Mapping[str, str] | None = None,
    ) -> "SecurityRemediationConfig":
        env = os.environ if env is None else env

        token = env.get(TOKEN_ENV, "")
        if not token:
            raise ConfigError(
                f"Missing {TOKEN_ENV} environment variable. "
                "Set it before running, for example: $env:GITHUB_TOKEN = (gh auth token)"
            )

        env_owner, _, env_repo = env.get(REPOSITORY_ENV, "").partition("/")
        resolved_owner = owner or env_owner
        resolved_repo = normalize_repo_name(repo or env_repo or "")
        if not resolved_owner or not resolved_repo:
            raise ConfigError(
                f"Repository owner and name are required (arguments or {REPOSITORY_ENV}=owner/name)"
            )

        return cls(
            owner=resolved_owner,
            repo=resolved_repo,
            github_token=token,
            ref=ref or env.get("SECURITY_REMEDIATION_REF") or None,
            ecosystems=parse_ecosystems(ecosystems if ecosystems else env.get(ECOSYSTEMS_ENV)),
            verification_enabled=parse_bool(
                verification_enabled if verification_enabled is not None else env.get(VERIFICATION_ENV),
                True,
                VERIFICATION_ENV,
            ),
            additional_updates=parse_bool(
                additional_updates if additional_updates is not None else env.get(ADDITIONAL_UPDATES_ENV),
                False,
                ADDITIONAL_UPDATES_ENV,
            ),
            artifact_output=parse_bool(
                artifact_output if artifact_output is not None else env.get(ARTIFACT_OUTPUT_ENV),
                True,
                ARTIFACT_OUTPUT_ENV,
            ),
        )
