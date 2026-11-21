from __future__ import annotations

import json
import logging
import re
from fnmatch import fnmatchcase
from typing import Any

from packaging.version import InvalidVersion, Version

from ...models.remediation_plan import RemeditionPackageBundle
from ...models.security_package_triage import SecurityPackageTriage
from ...tools.ecosystem_manifest_tool import DEFAULT_REF, RENOVATE_CONFIG_PATHS, ManifestTool

logger = logging.getLogger(__name__)


class RenovateGroupingEngine:
    """Fetch Renovate config and group remediation packages using packageRules."""

    @staticmethod
    def _strip_json5_comments(text: str) -> str:
        """Remove // and /* */ comments while leaving string literals untouched.

        A naive regex-based stripper would also match "//" appearing inside a
        string value (e.g. a "$schema": "https://..." URL) and corrupt it, so
        comments are only stripped when not inside a single- or double-quoted
        string.
        """
        result = []
        in_string: str | None = None
        i = 0
        length = len(text)
        while i < length:
            char = text[i]

            if in_string:
                result.append(char)
                if char == "\\" and i + 1 < length:
                    result.append(text[i + 1])
                    i += 2
                    continue
                if char == in_string:
                    in_string = None
                i += 1
                continue

            if char in ("'", '"'):
                in_string = char
                result.append(char)
                i += 1
                continue

            if char == "/" and i + 1 < length and text[i + 1] == "/":
                newline = text.find("\n", i)
                i = length if newline == -1 else newline
                continue

            if char == "/" and i + 1 < length and text[i + 1] == "*":
                end = text.find("*/", i + 2)
                i = length if end == -1 else end + 2
                continue

            result.append(char)
            i += 1

        return "".join(result)

    @staticmethod
    def parse_json5(raw_text: str) -> dict[str, Any]:
        cleaned = raw_text.strip()
        if not cleaned:
            return {}
        cleaned = RenovateGroupingEngine._strip_json5_comments(cleaned)
        cleaned = re.sub(r",\s*([}\]])", r"\1", cleaned)

        try:
            data = json.loads(cleaned)
            return data if isinstance(data, dict) else {}
        except json.JSONDecodeError:
            cleaned = re.sub(r"(?<!['\"])(?<![\w$])(\$?[A-Za-z0-9_.-]+)\s*:", r'"\1":', cleaned)
            cleaned = re.sub(r"'([^'\\]*(?:\\.[^'\\]*)*)'", r'"\1"', cleaned)
            data = json.loads(cleaned)
            return data if isinstance(data, dict) else {}

    @staticmethod
    def _matches(value: str, patterns: list[str]) -> bool:
        """Match exact names, globs and /regex/ patterns, including exclusions."""
        def match(pattern):
            if pattern.startswith("/") and pattern.endswith("/"):
                return re.search(pattern[1:-1], value, re.I) is not None
            return fnmatchcase(value.casefold(), pattern.casefold())

        positives = [p for p in patterns if not p.startswith("!")]
        return (not positives or any(match(p) for p in positives)) and not any(
            match(p[1:]) for p in patterns if p.startswith("!"))

    @staticmethod
    def _update_type(current: str, target: str) -> str:
        try:
            before, after = Version(current.lstrip("vV")), Version(target.lstrip("vV"))
        except InvalidVersion:
            return "unknown"
        if after <= before:
            return "unknown"
        return "major" if after.major != before.major else (
            "minor" if after.minor != before.minor else "patch")

    @staticmethod
    def group_packages_by_package_rules(
        packages: list[SecurityPackageTriage],
        config: dict[str, Any] | str | None,
    ) -> list[RemeditionPackageBundle]:
        """Group SecurityPackageTriage entries into bundles using Renovate packageRules.

        Match actual upgrade targets, including parents of transitive findings.
        Later matching group rules override earlier ones. Conflicting parent
        groups retain one default finding rather than duplicating advisory counts.
        """
        default_group_name = "default"

        if isinstance(config, str):
            config = RenovateGroupingEngine.parse_json5(config)

        rules = config.get("packageRules", []) if isinstance(config, dict) else []
        if isinstance(config, dict) and config.get("extends"):
            logger.warning("Renovate extends presets are not resolved; only local packageRules are applied: %s",
                           config["extends"])
        supported_matchers = {"matchPackageNames", "matchManagers", "matchDatasources", "matchUpdateTypes"}
        usable_rules = []
        for rule in rules:
            if not isinstance(rule, dict):
                logger.warning("Skipping invalid Renovate packageRule")
                continue
            if rule.get("enabled") is False:
                logger.warning("Skipping disabled Renovate grouping rule")
                continue
            unsupported = {key for key in rule if key.startswith(("match", "exclude"))
                           and key not in supported_matchers}
            if unsupported or rule.get("extends"):
                logger.warning("Skipping Renovate grouping rule with unsupported selectors or presets: %s",
                               sorted(unsupported) or rule.get("extends"))
                continue
            if "groupName" not in rule:
                continue
            if any(not isinstance(rule[key], list) or not all(isinstance(p, str) for p in rule[key])
                   for key in supported_matchers if key in rule):
                logger.warning("Skipping Renovate grouping rule with invalid matcher lists")
                continue
            usable_rules.append(rule)

        grouped: dict[tuple[str, str], list[SecurityPackageTriage]] = {}
        for package in packages:
            ecosystem = (package.ecosystem or "unknown").lower()
            manager, datasource = {
                "npm": ("npm", "npm"), "npm_and_yarn": ("npm", "npm"), "yarn": ("npm", "npm"),
                "pip": ("pip_requirements", "pypi"), "pypi": ("pip_requirements", "pypi"),
                "poetry": ("poetry", "pypi"), "nuget": ("nuget", "nuget"),
            }.get(ecosystem, (ecosystem, ecosystem))
            targets = [(r.package, r.from_version, r.minimum_patched_version)
                       for r in package.package_upgrade_recommendations]
            if not targets and package.istransitive:
                targets = [(p.package, p.version, "")
                           for occurrence in package.transitive_dependency_occurrences
                           for p in occurrence.introducers]
            if not targets:
                targets = [(package.package, package.current_version, package.vulnerablility_fixed_version)]
            target_groups = set()
            for name, current, target in targets:
                group = default_group_name
                for rule in usable_rules:
                    values = {"matchPackageNames": name, "matchManagers": manager,
                              "matchDatasources": datasource,
                              "matchUpdateTypes": RenovateGroupingEngine._update_type(current, target)}
                    try:
                        matches = all(RenovateGroupingEngine._matches(values[key], rule[key])
                                      for key in supported_matchers if key in rule)
                    except re.error:
                        logger.warning("Skipping Renovate grouping rule with unsupported/invalid regex")
                        continue
                    if matches:
                        group = rule.get("groupName") or default_group_name
                target_groups.add(group)
            matched_group = next(iter(target_groups)) if len(target_groups) == 1 else default_group_name
            if len(target_groups) > 1:
                logger.warning("Finding %s has upgrade targets in different Renovate groups %s; retaining default group",
                               package.package, sorted(target_groups))
            grouped.setdefault((ecosystem, matched_group), []).append(package)

        return [
            RemeditionPackageBundle(
                groupName=group_name,
                ecosystem=ecosystem,
                severity=None,
                packages=group_packages,
            )
            for (ecosystem, group_name), group_packages in grouped.items()
        ]

    @staticmethod
    async def fetch_renovate_config(
        owner: str,
        repo: str,
        ref: str | None = None,
        *,
        paths: list[str] | None = None,
        manifest_tool: ManifestTool | None = None,
    ) -> dict[str, Any] | None:
        """Fetch and parse the repository's renovate.json5 (or renovate.json) config."""
        if manifest_tool is None:
            logger.debug("fetch_renovate_config created its own ManifestTool; cache is not shared")
            manifest_tool = ManifestTool()
        candidates = paths or RENOVATE_CONFIG_PATHS

        for path in candidates:
            if manifest_tool.is_offline:
                cache = manifest_tool.cache.manifest_cache
                if not cache.has(cache.key(owner, repo, path, ref or DEFAULT_REF)):
                    raise ValueError(f"Renovate config was not collected: {path}")
            content = await manifest_tool.get(owner, repo, path, ref)
            if content is None:
                continue

            logger.info("Fetched renovate config content from %s/%s at path %s", owner, repo, path)
            try:
                return RenovateGroupingEngine.parse_json5(content)
            except (ValueError, json.JSONDecodeError) as exc:
                # Content was fetched successfully but isn't valid JSON5; this is a
                # real config problem, not a "file not found" -- don't mask it by
                # trying other candidate paths.
                raise ValueError(f"Failed to parse renovate config at {owner}/{repo}:{path}") from exc

        return None

    @staticmethod
    async def group_packages_from_github(
        packages: list[SecurityPackageTriage],
        owner: str,
        repo: str,
        ref: str | None = None,
        *,
        paths: list[str] | None = None,
        manifest_tool: ManifestTool | None = None,
    ) -> list[RemeditionPackageBundle] | None:
        """Fetch renovate.json5 from GitHub, then group packages by its packageRules."""
        config = await RenovateGroupingEngine.fetch_renovate_config(
            owner, repo, ref, paths=paths, manifest_tool=manifest_tool
        )
        if config is None:
            return None
        return RenovateGroupingEngine.group_packages_by_package_rules(packages, config)
