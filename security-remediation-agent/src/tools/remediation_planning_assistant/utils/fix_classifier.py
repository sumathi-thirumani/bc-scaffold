from ....models.remediation_plan import (
    FixClass,
    ActionType,
)

from ....models.security_package_triage import SecurityPackageTriage
from ....tools.github_pr_collector.model.pull_request_metadata import PullRequestMetadata



class FixClassifier:

# ── Fix classification helpers ────────────────────────────────────────────────

    @staticmethod
    def derive_fix_class(pkg: SecurityPackageTriage) -> FixClass:
        has_fix_direction = bool(
            pkg.non_breaking_upgrade_version
            or pkg.breaking_upgrade_version
            or pkg.upgrade_version
            or pkg.remediated_version
        )

        if not pkg.isupgradable and not has_fix_direction:
            return FixClass.NO_FIX_AVAILABLE

        has_non_breaking = bool(pkg.non_breaking_upgrade_version)
        has_breaking = bool(pkg.breaking_upgrade_version)

        if has_non_breaking and has_breaking:
            return FixClass.PARTIAL_FIX_AVAILABLE
        if has_breaking and not has_non_breaking:
            return FixClass.BREAKING_BUMP
        if has_non_breaking and not has_breaking:
            return FixClass.NON_BREAKING_BUMP

        if has_fix_direction:
            return FixClass.NON_BREAKING_BUMP

        return FixClass.NO_FIX_AVAILABLE

    @staticmethod
    def derive_action_type(
        pkg: SecurityPackageTriage,
        fix_class: FixClass,
    ) -> ActionType:
        if fix_class == FixClass.NO_FIX_AVAILABLE:
            return ActionType.OPEN_ISSUE

        if fix_class == FixClass.NON_BREAKING_BUMP:
            if pkg.non_breaking_pull_available and pkg.non_breaking_pull_metadata:
                return ActionType.ROLLUP_PR
            return ActionType.PLACEHOLDER_PR

        if fix_class == FixClass.BREAKING_BUMP:
            if pkg.breaking_pull_available and pkg.breaking_pull_metadata:
                return ActionType.STANDALONE_PR
            return ActionType.PLACEHOLDER_PR

        if fix_class == FixClass.PARTIAL_FIX_AVAILABLE:
            if pkg.non_breaking_pull_available and pkg.non_breaking_pull_metadata:
                return ActionType.ROLLUP_PR
            if pkg.breaking_pull_available and pkg.breaking_pull_metadata:
                return ActionType.STANDALONE_PR
            return ActionType.PLACEHOLDER_PR

        return ActionType.OPEN_ISSUE
    
    @staticmethod
    def derive_relationship(pkg: SecurityPackageTriage) -> str:
        if pkg.istransitive:
            return "transitive"
        if any(vulnerability.relationship.lower() == "direct" for vulnerability in pkg.vulnerabilities):
            return "direct"
        if pkg.vulnerabilities:
            return pkg.vulnerabilities[0].relationship
        return "unknown"