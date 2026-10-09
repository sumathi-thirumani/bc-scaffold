"""Minimal environment for subprocesses that execute third-party package code."""

import os
from collections.abc import Mapping

# Only what package managers need to run, reach a proxy and trust custom CAs.
# Credentials such as GITHUB_TOKEN are deliberately excluded.
_ALLOWED_ENV_VARS = frozenset(
    {
        "PATH",
        "HOME",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "SYSTEMROOT",
        "COMSPEC",
        "PATHEXT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "LANG",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "REQUESTS_CA_BUNDLE",
        "NODE_EXTRA_CA_CERTS",
    }
)


def minimal_subprocess_env(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    """Return an allowlisted copy of the environment plus ``extra`` overrides."""
    allowed = {name.upper() for name in _ALLOWED_ENV_VARS}
    env = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    env.update(extra or {})
    return env
