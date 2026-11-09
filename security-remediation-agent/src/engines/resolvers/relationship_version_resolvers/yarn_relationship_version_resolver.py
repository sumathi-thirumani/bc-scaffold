"""Resolve Yarn Classic and Berry dependency relationships with Yarn's JSON CLI output."""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
import tempfile
from collections.abc import Iterable
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from ....utils.subprocess_env import minimal_subprocess_env

logger = logging.getLogger(__name__)

_PACKAGE_VERSION = re.compile(
    r"(?P<name>@[^@\s]+/[^@\s]+|[^@\s#]+)@(?P<version>[^@\s]+)"
)
_QUOTED = re.compile(r'"([^"]+)"')
# Targets become argv (through yarn.cmd on Windows), so only valid npm names are allowed.
_PACKAGE_NAME = re.compile(r"^(@[a-z0-9~][a-z0-9._~-]*/)?[a-z0-9~][a-z0-9._~-]*$", re.IGNORECASE)
# Yarn Classic exits non-zero when ``why`` finds no matching package.
_NOT_FOUND = re.compile(r"couldn'?t find a match|could not find a match|couldn'?t find package", re.IGNORECASE)
MAX_PATHS_PER_TARGET = 200


class YarnPackageNotFound(subprocess.SubprocessError):
    """Yarn reported that the target package is not in the project."""


class YarnRelationshipVersionResolver:
    """Identify direct/transitive dependencies with Yarn Classic or Berry JSON output.

    ``prefetch`` raises ``SubprocessError`` or ``OSError`` when Yarn itself fails. A
    package that Yarn cannot find is a normal empty result and never aborts other
    targets. Results are cached by package name for this resolver instance.
    Inputs are staged as package.json and yarn.lock only; workspace manifests
    and repository-specific Yarn configuration are not reconstructed.
    """

    def __init__(
        self,
        lock_text: str,
        package_text: str,
        *,
        yarn_executable: str | None = None,
        timeout_seconds: int = 60,
    ) -> None:
        """Retain manifest inputs, detect Yarn generation, and locate the CLI executable."""
        if not lock_text or not package_text:
            raise ValueError("package.json and yarn.lock content are required")
        self.lock_text = lock_text
        self.package_text = package_text
        self.yarn_major = self._detect_yarn_major(package_text, lock_text)
        self.direct = self._direct_dependencies(package_text)
        self.yarn = (
            yarn_executable
            or shutil.which("yarn")
            or shutil.which("yarn.cmd")
        )
        if not self.yarn:
            raise OSError("yarn executable not found")
        self.timeout_seconds = timeout_seconds
        self._results: dict[str, dict[str, Any]] = {}

    def resolve(self, target: str) -> dict[str, Any]:
        """Return cached occurrences, resolving an unseen target on demand."""
        key = target.casefold()
        if key not in self._results:
            self.prefetch([target])
        return self._results.get(key) or {"package": target, "occurrences": []}

    def prefetch(self, names: Iterable[str]) -> None:
        """Stage inputs once per batch and resolve uncached targets independently."""
        targets = list(dict.fromkeys(names))
        targets = [name for name in targets if name.casefold() not in self._results]
        if not targets:
            return

        with tempfile.TemporaryDirectory(prefix="yarn_relationship_") as tmp:
            directory = Path(tmp)
            (directory / "package.json").write_text(self.package_text, encoding="utf-8")
            (directory / "yarn.lock").write_text(self.lock_text, encoding="utf-8")

            for target in targets:
                if not _PACKAGE_NAME.match(target):
                    logger.warning("Ignoring invalid package name %r", target)
                    paths, versions = [], {}
                else:
                    try:
                        paths, versions = self._why(directory, target)
                    except YarnPackageNotFound:
                        paths, versions = [], {}
                self._results[target.casefold()] = self._build_result(target, paths, versions)

    def _why(
        self, directory: Path, target: str
    ) -> tuple[list[list[tuple[str, str]]], dict[str, list[str]]]:
        """Collect paths and versions using the command supported by this Yarn generation."""
        if self.yarn_major >= 2:
            output = self._run_yarn(directory, "why", target, "--recursive", "--json")
            return self._cap(self._parse_berry_why(output, target), target), {}

        output = self._run_yarn(directory, "why", target, "--json")
        paths = self._cap(self._parse_classic_why(output, target), target)
        if not paths and target.casefold() in self.direct:
            paths = [[(target, "")]]
        package_names = {package for path in paths for package, _ in path} | {target}
        versions = self._parse_versions(
            self._run_yarn(
                directory,
                "list",
                "--pattern",
                "|".join(re.escape(name) for name in sorted(package_names)),
                "--json",
            ),
            package_names,
        )
        return paths, versions

    @staticmethod
    def _cap(paths: list[list[tuple[str, str]]], target: str) -> list[list[tuple[str, str]]]:
        """Limit retained dependency paths and warn when parsed paths exceed the limit."""
        if len(paths) > MAX_PATHS_PER_TARGET:
            logger.warning("Truncating dependency paths for %s at %d", target, MAX_PATHS_PER_TARGET)
        return paths[:MAX_PATHS_PER_TARGET]

    @staticmethod
    def _detect_yarn_major(package_text: str, lock_text: str) -> int:
        """Prefer packageManager metadata, then Berry lock metadata, else Classic."""
        try:
            package = json.loads(package_text)
        except json.JSONDecodeError:
            package = {}
        manager = package.get("packageManager", "") if isinstance(package, dict) else ""
        match = re.match(r"yarn@(\d+)", manager)
        if match:
            return int(match.group(1))
        if re.search(r"^__metadata:", lock_text, re.MULTILINE):
            return 2
        return 1

    @staticmethod
    def _direct_dependencies(package_text: str) -> set[str]:
        """Installed direct dependencies; peers are not installed by this project."""
        try:
            package = json.loads(package_text)
        except json.JSONDecodeError:
            return set()
        if not isinstance(package, dict):
            return set()
        names = set()
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            entries = package.get(section, {})
            if isinstance(entries, dict):
                names.update(name.casefold() for name in entries)
        return names

    def _run_yarn(self, directory: Path, *arguments: str) -> str:
        """Run Yarn with a timeout, distinguishing absent targets from command failures."""
        result = subprocess.run(
            [self.yarn, *arguments],
            cwd=directory,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=self.timeout_seconds,
            env=minimal_subprocess_env({"NO_COLOR": "1"}),
        )
        if result.returncode != 0:
            message = (
                f"yarn {' '.join(arguments)} failed with exit code "
                f"{result.returncode}: {result.stderr.strip()[:500]}"
            )
            if _NOT_FOUND.search(f"{result.stderr}\n{result.stdout}"):
                raise YarnPackageNotFound(message)
            raise subprocess.SubprocessError(message)
        return result.stdout

    @staticmethod
    def _json_lines(output: str) -> list[dict[str, Any]]:
        """Read JSON object events from CLI output, ignoring non-JSON lines."""
        events = []
        for line in output.splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(event, dict):
                events.append(event)
        return events

    @classmethod
    def _parse_classic_why(
        cls, output: str, target: str
    ) -> list[list[tuple[str, str]]]:
        """Extract quoted hash-separated package chains from Classic message events."""
        paths: list[list[tuple[str, str]]] = []
        target_key = target.casefold()
        for event in cls._json_lines(output):
            data = event.get("data")
            values = [data] if isinstance(data, str) else []
            values.extend(cls._strings(data))
            for value in values:
                for quoted in _QUOTED.findall(value):
                    parts = quoted.split("#")
                    if (
                        not parts
                        or cls._package_name(parts[-1]).casefold() != target_key
                    ):
                        continue
                    path = [(cls._package_name(part), "") for part in parts]
                    if path not in paths:
                        paths.append(path)
        return paths

    @classmethod
    def _parse_berry_why(
        cls, output: str, target: str
    ) -> list[list[tuple[str, str]]]:
        """Traverse Berry JSON trees and omit workspace locators from returned paths."""
        paths: list[list[tuple[str, str]]] = []

        def visit(node: Any, path: list[tuple[str, str]]) -> None:
            """Walk nested tree values and children until the target path limit is reached."""
            if len(paths) >= MAX_PATHS_PER_TARGET:
                return
            if isinstance(node, list):
                for child in node:
                    visit(child, path)
                return
            if not isinstance(node, dict):
                return

            value = node.get("value", node)
            locator = value if isinstance(value, str) else (
                value.get("locator") if isinstance(value, dict) else None
            )
            next_path = path
            if isinstance(locator, str):
                name, version, reference = cls._parse_locator(locator)
                if name and not reference.startswith("workspace:"):
                    next_path = [*path, (name, version)]
                    if name.casefold() == target.casefold() and next_path not in paths:
                        paths.append(next_path)

            children = node.get("children")
            if isinstance(children, dict):
                for child in children.values():
                    visit(child, next_path)
            elif isinstance(children, list):
                visit(children, next_path)

        for event in cls._json_lines(output):
            visit(event, [])
        return paths

    @staticmethod
    def _parse_locator(locator: str) -> tuple[str, str, str]:
        """Extract a package name, npm version when available, and original reference."""
        match = re.match(r"(?P<name>@[^/]+/[^@]+|[^@]+)@(?P<reference>.+)$", locator)
        if not match:
            return "", "", ""
        name = match.group("name")
        reference = match.group("reference")
        decoded = unquote(reference)
        npm_match = re.search(r"(?:^|[@#])npm:(\d[^#]*)", decoded)
        version = npm_match.group(1).split("&", 1)[0] if npm_match else ""
        return name, version, reference

    @staticmethod
    def _package_name(value: str) -> str:
        """Remove a Yarn ``@version`` suffix while preserving scoped names."""
        if value.startswith("@"):
            separator = value.find("@", 1)
            return value if separator < 0 else value[:separator]
        return value.rsplit("@", 1)[0] if "@" in value else value

    @staticmethod
    def _strings(value: Any) -> list[str]:
        """Flatten nested JSON values into strings for Classic output parsing."""
        if isinstance(value, dict):
            return [
                string
                for child in value.values()
                for string in YarnRelationshipVersionResolver._strings(child)
            ]
        if isinstance(value, list):
            return [
                string
                for child in value
                for string in YarnRelationshipVersionResolver._strings(child)
            ]
        return [value] if isinstance(value, str) else []

    @staticmethod
    def _parse_versions(
        output: str, package_names: set[str]
    ) -> dict[str, list[str]]:
        """Collect distinct listed versions for the requested package names."""
        versions: dict[str, list[str]] = {}
        expected = {name.casefold() for name in package_names}
        for event in YarnRelationshipVersionResolver._json_lines(output):
            for value in YarnRelationshipVersionResolver._strings(event):
                for match in _PACKAGE_VERSION.finditer(value):
                    name = match.group("name")
                    if name.casefold() not in expected:
                        continue
                    versions.setdefault(name.casefold(), [])
                    if match.group("version") not in versions[name.casefold()]:
                        versions[name.casefold()].append(match.group("version"))
        return versions

    @staticmethod
    def _build_result(
        target: str,
        paths: list[list[tuple[str, str]]],
        versions: dict[str, list[str]],
    ) -> dict[str, Any]:
        """Group paths by target version, retaining introducers and direct-root evidence."""
        def known_version(name: str) -> str:
            # Classic paths carry no versions; guessing among several would mislabel paths.
            """Use a listed version only when it is unambiguous; otherwise return empty."""
            found = versions.get(name.casefold(), [])
            return found[0] if len(found) == 1 else ""

        by_version: dict[str, dict[str, Any]] = {}
        for path in paths:
            version = path[-1][1] or known_version(target)
            occurrence = by_version.setdefault(
                version,
                {
                    "package": target,
                    "version": version or None,
                    "introducers": [],
                    "is_root": False,
                    "paths": [],
                },
            )
            if len(path) == 1:
                occurrence["is_root"] = True
            else:
                introducer_name = path[0][0]
                introducer = {
                    "package": introducer_name,
                    "version": path[0][1] or known_version(introducer_name),
                }
                if introducer not in occurrence["introducers"]:
                    occurrence["introducers"].append(introducer)
            rendered = [
                f"{name}@{path_version or known_version(name)}"
                for name, path_version in path
            ]
            if rendered not in occurrence["paths"]:
                occurrence["paths"].append(rendered)
        return {
            "package": target,
            "occurrences": list(by_version.values()),
        }
