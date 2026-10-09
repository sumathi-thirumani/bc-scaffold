from dataclasses import dataclass, field

@dataclass
class VulnerabilitySummary:
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    others: int = 0

@dataclass
class ManifestCache:
    """Run-scoped store of manifest text keyed by repository snapshot and path.

    Lockfiles are intentionally not stored here; only declaration manifests are
    reused across alerts. Entries live in a non-field attribute so manifest
    content never leaks into ``asdict()`` output of the remediation plan.
    """

    def __post_init__(self) -> None:
        self._entries: dict[tuple[str, str, str | None, str], str | None] = {}
        self._packages: dict[
            tuple[str, str, str | None, str], dict[str, dict[str, str | None]]
        ] = {}

    @staticmethod
    def key(owner: str, repo: str, path: str, ref: str | None) -> tuple[str, str, str | None, str]:
        return (owner.lower(), repo.lower(), ref, path.lstrip("/"))

    def has(self, key: tuple[str, str, str | None, str]) -> bool:
        return key in self._entries

    def get(self, key: tuple[str, str, str | None, str]) -> str | None:
        return self._entries.get(key)

    def set(self, key: tuple[str, str, str | None, str], text: str | None) -> None:
        self._entries[key] = text

    def clear(self) -> None:
        """Discard cached manifests, for example before starting another run."""
        self._entries.clear()
        self._packages.clear()

    def get_packages(
        self, key: tuple[str, str, str | None, str]
    ) -> dict[str, str | None] | None:
        return self._packages.get(key)

    def set_packages(
        self,
        key: tuple[str, str, str | None, str],
        ecosystem: str,
        packages: dict[str, str | None],
    ) -> None:
        self._packages.setdefault(key, {})[ecosystem.lower()] = packages


@dataclass
class ManifestLockCache:
    """Run-scoped lockfile text keyed by repository snapshot and path."""

    def __post_init__(self) -> None:
        self._entries: dict[tuple[str, str, str | None, str], str | None] = {}

    @staticmethod
    def key(
        owner: str,
        repo: str,
        path: str,
        ref: str | None,
    ) -> tuple[str, str, str | None, str]:
        return (owner.lower(), repo.lower(), ref, path.lstrip("/"))

    def has(self, key: tuple[str, str, str | None, str]) -> bool:
        return key in self._entries

    def get(self, key: tuple[str, str, str | None, str]) -> str | None:
        return self._entries.get(key)

    def set(self, key: tuple[str, str, str | None, str], text: str | None) -> None:
        self._entries[key] = text

    def clear(self) -> None:
        self._entries.clear()


@dataclass
class SecurityRemediationCache:
    manifest_cache: ManifestCache = field(default_factory=ManifestCache, repr=False, compare=False)
    manifest_lock_cache: ManifestLockCache = field(
        default_factory=ManifestLockCache,
        repr=False,
        compare=False,
    )

@dataclass
class SecurityRemediationContext:
    total_vulnerabilities: int = 0
    total_code_scanning_alerts: int = 0
    total_reviewed_prs: int = 0
    total_ignored_prs: int = 0
    total_remediation_prs: int = 0
    vulnerabilities_summary: VulnerabilitySummary = field(default_factory=VulnerabilitySummary)
