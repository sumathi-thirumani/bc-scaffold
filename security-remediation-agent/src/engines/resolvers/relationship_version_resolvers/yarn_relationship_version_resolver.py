"""Resolve Yarn Classic dependency relationships with Yarn's JSON CLI output."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from ....utils.subprocess_env import minimal_subprocess_env

_PACKAGE_VERSION = re.compile(
    r"(?P<name>@[^@\s]+/[^@\s]+|[^@\s#]+)@(?P<version>[^@\s]+)"
)
_QUOTED = re.compile(r'"([^"]+)"')


class YarnRelationshipVersionResolver:
    """Identify Yarn v1 direct/transitive dependencies and their versions."""

    def __init__(
        self,
        lock_text: str,
        package_text: str,
        *,
        yarn_executable: str | None = None,
        timeout_seconds: int = 60,
    ) -> None:
        if not lock_text or not package_text:
            raise ValueError("package.json and yarn.lock content are required")
        self.lock_text = lock_text
        self.package_text = package_text
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
        key = target.casefold()
        if key not in self._results:
            self.prefetch([target])
        return self._results.get(key) or {"package": target, "occurrences": []}

    def prefetch(self, names: Iterable[str]) -> None:
        targets = list(dict.fromkeys(names))
        targets = [name for name in targets if name.casefold() not in self._results]
        if not targets:
            return

        with tempfile.TemporaryDirectory(prefix="yarn_relationship_") as tmp:
            directory = Path(tmp)
            (directory / "package.json").write_text(self.package_text, encoding="utf-8")
            (directory / "yarn.lock").write_text(self.lock_text, encoding="utf-8")

            for target in targets:
                why_output = self._run_yarn(
                    directory, "why", target, "--recursive", "--json"
                )
                paths = self._parse_why(why_output, target)
                package_names = {
                    package
                    for path in paths
                    for package, _ in path
                }
                package_names.add(target)
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
                self._results[target.casefold()] = self._build_result(
                    target, paths, versions
                )

    def _run_yarn(self, directory: Path, *arguments: str) -> str:
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
            raise subprocess.SubprocessError(
                f"yarn {' '.join(arguments)} failed with exit code "
                f"{result.returncode}: {result.stderr.strip()[:500]}"
            )
        return result.stdout

    @staticmethod
    def _json_lines(output: str) -> list[dict[str, Any]]:
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
    def _parse_why(
        cls, output: str, target: str
    ) -> list[list[tuple[str, str]]]:
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
        if not paths:
            paths.append([(target, "")])
        return paths

    @staticmethod
    def _package_name(value: str) -> str:
        """Remove a Yarn ``@version`` suffix while preserving scoped names."""
        if value.startswith("@"):
            separator = value.find("@", 1)
            return value if separator < 0 else value[:separator]
        return value.rsplit("@", 1)[0] if "@" in value else value

    @staticmethod
    def _strings(value: Any) -> list[str]:
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
        target_versions = versions.get(target.casefold(), [])
        by_version: dict[str, dict[str, Any]] = {}
        for path in paths:
            version = target_versions[0] if target_versions else ""
            if path and path[-1][1]:
                version = path[-1][1]
            occurrence = by_version.setdefault(
                version,
                {
                    "package": target,
                    "version": version or None,
                    "introducers": [],
                    "is_root": len(path) == 1,
                    "paths": [],
                },
            )
            if len(path) > 1:
                introducer_name = path[0][0]
                introducer_versions = versions.get(introducer_name.casefold(), [])
                introducer = {
                    "package": introducer_name,
                    "version": introducer_versions[0] if introducer_versions else "",
                }
                if introducer not in occurrence["introducers"]:
                    occurrence["introducers"].append(introducer)
                occurrence["is_root"] = False
            rendered = [
                f"{name}@{versions.get(name.casefold(), [''])[0] or version}"
                for name, _ in path
            ]
            if rendered not in occurrence["paths"]:
                occurrence["paths"].append(rendered)
        return {"package": target, "occurrences": list(by_version.values())}

