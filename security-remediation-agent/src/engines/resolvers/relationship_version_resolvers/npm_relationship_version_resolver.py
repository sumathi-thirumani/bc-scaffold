"""Resolve npm direct and transitive dependency versions with the npm CLI."""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from ....utils.subprocess_env import minimal_subprocess_env

logger = logging.getLogger(__name__)


class NpmRelationshipVersionResolver:
    """Identify npm relationships using the full ``npm ls`` lockfile tree."""

    def __init__(
        self,
        lock_text: str,
        package_text: str,
        *,
        npm_executable: str | None = None,
        timeout_seconds: int = 60,
    ) -> None:
        if not lock_text or not package_text:
            raise ValueError("package.json and package-lock.json content are required")
        self.lock_text = lock_text
        self.package_text = package_text
        self.npm = npm_executable or shutil.which("npm") or shutil.which("npm.cmd")
        if not self.npm:
            raise OSError("npm executable not found")
        self.timeout_seconds = timeout_seconds
        self._results: dict[str, dict[str, Any]] = {}

    def resolve(self, target: str) -> dict[str, Any]:
        if target not in self._results:
            self.prefetch([target])
        return self._results.get(target) or {"package": target, "occurrences": []}

    def prefetch(self, names: Iterable[str]) -> None:
        targets = [name for name in dict.fromkeys(names) if name not in self._results]
        if not targets:
            return
        with tempfile.TemporaryDirectory(prefix="npm_relationship_") as tmp:
            directory = Path(tmp)
            (directory / "package.json").write_text(self.package_text, encoding="utf-8")
            (directory / "package-lock.json").write_text(self.lock_text, encoding="utf-8")
            tree = self._run_npm_ls(directory, targets)
            matches = self._collect(tree, set(targets))
            for name in targets:
                self._results[name] = self._build_result(name, matches.get(name, []))

    def _run_npm_ls(self, directory: Path, names: list[str]) -> dict[str, Any]:
        result = subprocess.run(
            [self.npm, "ls", *names, "--all", "--package-lock-only", "--json"],
            cwd=directory,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=self.timeout_seconds,
            env=minimal_subprocess_env({"NO_COLOR": "1"}),
        )
        try:
            tree = json.loads(result.stdout or "")
        except json.JSONDecodeError as exc:
            raise subprocess.SubprocessError(
                f"npm ls returned no JSON: {result.stderr.strip()[:500]}"
            ) from exc
        if not isinstance(tree, dict):
            raise subprocess.SubprocessError("npm ls returned unexpected JSON")
        if result.returncode != 0:
            logger.debug("npm ls exited %s: %s", result.returncode, result.stderr.strip()[:500])
        return tree

    def _collect(
        self,
        tree: dict[str, Any],
        targets: set[str],
    ) -> dict[str, list[list[tuple[str, str]]]]:
        matches: dict[str, list[list[tuple[str, str]]]] = {}
        stack: list[tuple[dict[str, Any], list[tuple[str, str]]]] = [(tree, [])]
        while stack:
            node, path = stack.pop()
            for key, child in (node.get("dependencies") or {}).items():
                if not isinstance(child, dict):
                    continue
                version = child.get("version") or ""
                child_path = path + [(key, version)]
                if key in targets:
                    matches.setdefault(key, []).append(child_path)
                if (key, version) in path:
                    continue
                stack.append((child, child_path))
        return matches

    @staticmethod
    def _build_result(
        target: str,
        paths: list[list[tuple[str, str]]],
    ) -> dict[str, Any]:
        by_version: dict[str, dict[str, Any]] = {}
        for path in paths:
            version = path[-1][1]
            occurrence = by_version.setdefault(version, {
                "package": target,
                "version": version or None,
                "introducers": [],
                "is_root": len(path) == 1,
                "paths": [],
            })
            occurrence["is_root"] = occurrence["is_root"] or len(path) == 1
            if len(path) > 1:
                introducer = {"package": path[0][0], "version": path[0][1]}
                if introducer not in occurrence["introducers"]:
                    occurrence["introducers"].append(introducer)
            rendered = [f"{name}@{version}" for name, version in path]
            if rendered not in occurrence["paths"]:
                occurrence["paths"].append(rendered)
        return {
            "package": target,
            "occurrences": [by_version[version] for version in sorted(by_version)],
        }

