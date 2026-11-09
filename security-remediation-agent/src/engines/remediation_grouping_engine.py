from __future__ import annotations

import json
import logging
import re
from typing import Any

from ..models.remediation_plan import RemeditionPackageBundle
from ..models.security_package_triage import SecurityPackageTriage
from ..tools.ecosystem_manifest_tool import DEFAULT_REF, RENOVATE_CONFIG_PATHS, ManifestTool

logger = logging.getLogger(__name__)


class RemediationGroupingEngine:
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
        cleaned = RemediationGroupingEngine._strip_json5_comments(cleaned)
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
    def group_packages_by_package_rules(
        packages: list[SecurityPackageTriage],
        config: dict[str, Any] | str | None,
    ) -> list[RemeditionPackageBundle]:
        """Group SecurityPackageTriage entries into bundles using Renovate packageRules.

        Each package's `package` name is checked against each rule's
        `matchPackageNames`. The first matching rule's `groupName` becomes the bundle
        name. Packages that don't match any rule fall back to a "default" group.
        Each ecosystem gets a separate bundle even when group names are shared.
        """
        default_group_name = "default"

        if isinstance(config, str):
            config = RemediationGroupingEngine.parse_json5(config)

        rules = config.get("packageRules", []) if isinstance(config, dict) else []

        grouped: dict[tuple[str, str], list[SecurityPackageTriage]] = {}
        for package in packages:
            matched_group = default_group_name
            for rule in rules:
                match_names = rule.get("matchPackageNames", [])
                if package.package in match_names:
                    matched_group = rule.get("groupName") or default_group_name
                    break
            ecosystem = (package.ecosystem or "unknown").lower()
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
                return RemediationGroupingEngine.parse_json5(content)
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
        config = await RemediationGroupingEngine.fetch_renovate_config(
            owner, repo, ref, paths=paths, manifest_tool=manifest_tool
        )
        if config is None:
            return None
        return RemediationGroupingEngine.group_packages_by_package_rules(packages, config)
