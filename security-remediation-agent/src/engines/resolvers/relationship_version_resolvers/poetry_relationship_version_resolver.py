"""Resolve Poetry dependency paths with ``poetry show <package> --tree --why``.

``--why`` only lists a package's immediate requirers, so full paths are built by
walking upward, one Poetry call per ancestor, until a directly declared package is
reached. Poetry runs through ``uv tool run poetry`` (or ``poetry`` on PATH) against
a temporary copy of pyproject.toml and poetry.lock; nothing is installed or modified.
Direct dependencies are read from pyproject.toml because ``--why`` does not report
them when a package also has requirers.
"""

from __future__ import annotations

import importlib.util
import logging
import re
import shutil
import subprocess
import sys
import tempfile
from collections import defaultdict
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement

from ....utils.subprocess_env import minimal_subprocess_env

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib

logger = logging.getLogger(__name__)

# Targets become argv, so only valid Python distribution names are allowed.
_PACKAGE_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")
_HEADER = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*) (?P<version>\S+)(?:\s.*)?$")
_CHILD = re.compile(r"^[|`]-- (?P<name>\S+)(?: (?P<constraint>.*))?$")
_NOT_FOUND = re.compile(r"not found", re.IGNORECASE)
MAX_PATHS_PER_TARGET = 200
MAX_POETRY_CALLS = 200


class _CallBudgetExceeded(Exception):
    """The per-resolver cap on Poetry invocations was reached."""


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _declaration(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        extras = value.get("extras", [])
        return {
            "version": value.get("version", "*"),
            "markers": value.get("markers") or value.get("marker"),
            "extras": sorted(extras) if isinstance(extras, list) else [],
        }
    if isinstance(value, str):
        return {"version": value, "markers": None, "extras": []}
    raise ValueError(f"Unsupported dependency declaration: {value!r}")


def direct_declarations(project: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Collect every declared dependency (all groups and extras) by normalized name."""
    roots: dict[str, list[dict[str, Any]]] = defaultdict(list)

    def add_requirements(requirements: Iterable[Any], origin: str) -> None:
        for requirement in requirements:
            if not isinstance(requirement, str):
                continue  # PEP 735 include-group entries; all groups are read anyway
            try:
                parsed = Requirement(requirement)
            except InvalidRequirement as error:
                logger.warning("Skipping requirement in %s: %s", origin, error)
                continue
            roots[normalize(parsed.name)].append({
                "version": str(parsed.specifier) or "*",
                "markers": str(parsed.marker) if parsed.marker else None,
                "extras": sorted(parsed.extras),
                "origin": origin,
            })

    standard = project.get("project", {})
    if "dependencies" in standard.get("dynamic", []):
        logger.warning("Dynamic project dependencies cannot be read statically")
    add_requirements(standard.get("dependencies", []), "project.dependencies")
    for group, requirements in standard.get("optional-dependencies", {}).items():
        add_requirements(requirements, f"project.optional-dependencies.{group}")

    poetry = project.get("tool", {}).get("poetry", {})
    sections = [
        ("tool.poetry.dependencies", poetry.get("dependencies", {})),
        ("tool.poetry.dev-dependencies", poetry.get("dev-dependencies", {})),
    ]
    for group, data in poetry.get("group", {}).items():
        sections.append((f"tool.poetry.group.{group}", data.get("dependencies", {})))
    for origin, dependencies in sections:
        for name, value in dependencies.items():
            if normalize(name) == "python":
                continue
            # Poetry allows a list of constraint tables for one dependency.
            for item in value if isinstance(value, list) else [value]:
                try:
                    roots[normalize(name)].append({**_declaration(item), "origin": origin})
                except ValueError as error:
                    logger.warning("Skipping %s in %s: %s", name, origin, error)

    for group, requirements in project.get("dependency-groups", {}).items():
        add_requirements(requirements, f"dependency-groups.{group}")
    return dict(roots)


def parse_why_output(output: str, target_key: str) -> list[tuple[str, str, str | None]]:
    """Return ``(name, version, constraint)`` for each requirer in ``--tree --why`` output."""
    parents: list[list[Any]] = []
    for raw_line in output.splitlines():
        line = raw_line.rstrip()
        if not line or line.startswith("Package "):
            continue
        header = _HEADER.match(line)
        if header:
            parents.append([header["name"], header["version"], None])
            continue
        child = _CHILD.match(line)
        if (
            child
            and parents
            and parents[-1][2] is None
            and normalize(child["name"]) == target_key
        ):
            parents[-1][2] = (child["constraint"] or "").strip() or "*"
    return [(name, version, constraint) for name, version, constraint in parents]


class PoetryRelationshipVersionResolver:
    """Identify direct/transitive Poetry dependencies using ``poetry show --tree --why``.

    ``prefetch`` raises ``SubprocessError`` or ``OSError`` when Poetry itself fails.
    A package absent from the lock is a normal empty result. Results are cached by
    package name. Poetry reports one version per package, so a package locked at
    several versions yields ``version=None``.
    """

    def __init__(
        self,
        lock_text: str,
        project_text: str,
        *,
        poetry_command: list[str] | None = None,
        timeout_seconds: int = 60,
        max_paths: int = MAX_PATHS_PER_TARGET,
        max_calls: int = MAX_POETRY_CALLS,
    ) -> None:
        if not lock_text or not project_text:
            raise ValueError("pyproject.toml and poetry.lock content are required")
        self.lock_text = lock_text
        self.project_text = project_text
        self.command = poetry_command or self._find_command()
        self.timeout_seconds = timeout_seconds
        self.max_paths = max_paths
        self.max_calls = max_calls

        self.declarations = direct_declarations(tomllib.loads(project_text))
        self.direct = set(self.declarations)
        self.locked: dict[str, list[str | None]] = defaultdict(list)
        self.names: dict[str, str] = {}
        for entry in tomllib.loads(lock_text).get("package", []):
            key = normalize(entry["name"])
            self.names[key] = entry["name"]
            if entry.get("version") not in self.locked[key]:
                self.locked[key].append(entry.get("version"))

        self._requirers: dict[str, list[tuple[str, str, str | None]]] = {}
        self._edges: dict[tuple[str, str], str | None] = {}
        self._calls = 0
        self._results: dict[str, dict[str, Any]] = {}

    @staticmethod
    def _find_command() -> list[str]:
        uv = shutil.which("uv")
        if uv:
            return [uv, "tool", "run", "poetry"]
        if importlib.util.find_spec("uv"):
            return [sys.executable, "-m", "uv", "tool", "run", "poetry"]
        poetry = shutil.which("poetry")
        if poetry:
            return [poetry]
        raise OSError("neither uv nor poetry executable found")

    def resolve(self, target: str) -> dict[str, Any]:
        key = normalize(target)
        if key not in self._results:
            self.prefetch([target])
        return self._results.get(key) or {"package": target, "occurrences": []}

    def prefetch(self, names: Iterable[str]) -> None:
        targets = [
            name for name in dict.fromkeys(names) if normalize(name) not in self._results
        ]
        if not targets:
            return
        with tempfile.TemporaryDirectory(prefix="poetry_relationship_") as tmp:
            directory = Path(tmp)
            (directory / "pyproject.toml").write_text(self.project_text, encoding="utf-8")
            (directory / "poetry.lock").write_text(self.lock_text, encoding="utf-8")
            for target in targets:
                key = normalize(target)
                if not _PACKAGE_NAME.match(target):
                    logger.warning("Ignoring invalid package name %r", target)
                    self._results[key] = {"package": target, "occurrences": []}
                elif key not in self.locked:
                    self._results[key] = {"package": target, "occurrences": []}
                else:
                    self._results[key] = self._build(directory, key)

    def _run(self, directory: Path, name: str) -> str:
        if self._calls >= self.max_calls:
            raise _CallBudgetExceeded
        self._calls += 1
        result = subprocess.run(
            [*self.command, "show", name, "--tree", "--why"],
            cwd=directory,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=self.timeout_seconds,
            env=minimal_subprocess_env({
                "NO_COLOR": "1",
                "POETRY_NO_INTERACTION": "1",
                "POETRY_VIRTUALENVS_CREATE": "false",
            }),
        )
        if result.returncode != 0:
            if _NOT_FOUND.search(f"{result.stdout}\n{result.stderr}"):
                return ""
            raise subprocess.SubprocessError(
                f"poetry show {name} --tree --why failed with exit code "
                f"{result.returncode}: {result.stderr.strip()[:500]}"
            )
        return result.stdout

    def _parents(self, directory: Path, key: str) -> list[tuple[str, str, str | None]]:
        if key not in self._requirers:
            parents = parse_why_output(self._run(directory, self.names.get(key, key)), key)
            self._requirers[key] = parents
            for name, version, constraint in parents:
                parent_key = normalize(name)
                self.names.setdefault(parent_key, name)
                self.locked.setdefault(parent_key, [version])
                self._edges[(parent_key, key)] = constraint
        return self._requirers[key]

    def _version(self, key: str) -> str | None:
        versions = self.locked.get(key, [])
        return versions[0] if len(versions) == 1 else None

    def _node(self, key: str, constraint: str | None = None) -> dict[str, Any]:
        node: dict[str, Any] = {"package": self.names.get(key, key), "version": self._version(key)}
        if constraint is not None:
            node["dependency_conditions"] = [{"version": constraint}]
        return node

    def _build(self, directory: Path, target_key: str) -> dict[str, Any]:
        paths: list[list[str]] = []
        truncated = False
        pending: list[tuple[str, ...]] = [(target_key,)]
        while pending:
            reverse_path = pending.pop()
            current = reverse_path[-1]
            is_direct = current in self.direct
            if is_direct:
                paths.append(list(reversed(reverse_path)))
                if len(paths) >= self.max_paths:
                    truncated = bool(pending)
                    break
            # A direct ancestor ends its path; only the target also looks upward.
            if is_direct and current != target_key:
                continue
            try:
                parents = self._parents(directory, current)
            except _CallBudgetExceeded:
                logger.warning("Poetry call budget reached resolving %s", target_key)
                truncated = True
                continue
            for name, _, _ in sorted(parents, key=lambda parent: parent[0], reverse=True):
                parent_key = normalize(name)
                if parent_key not in reverse_path:
                    pending.append((*reverse_path, parent_key))

        path_details = []
        for path in paths:
            rendered = [self._node(path[0])]
            for parent, child in zip(path, path[1:], strict=False):
                rendered.append(self._node(child, self._edges.get((parent, child))))
            path_details.append(rendered)
        introducers = {
            path[0]: self._node(path[0]) for path in paths if path[0] != target_key
        }
        target_name = self.names.get(target_key, target_key)
        version = self._version(target_key)
        occurrence = {
            "package": target_name,
            "version": version,
            "introducers": [introducers[key] for key in sorted(introducers)],
            "is_root": target_key in self.direct,
            "paths": path_details,
            "paths_truncated": truncated,
            "declared_in": sorted({
                declaration["origin"] for declaration in self.declarations.get(target_key, [])
            }),
            "resolution_scope": "poetry show --tree --why over poetry.lock; markers not evaluated",
        }
        return {"package": target_name, "version": version, "occurrences": [occurrence]}
