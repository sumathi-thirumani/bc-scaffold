"""Resolve pip relationships from a non-installing JSON resolution report."""

from __future__ import annotations

import json
import logging
import re
import shlex
import subprocess
import sys
import tempfile
from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from ....utils.subprocess_env import minimal_subprocess_env

logger = logging.getLogger(__name__)


@dataclass
class _Package:
    """Package identity, direct-request flag, and dependency metadata from pip."""

    name: str
    version: str
    requested: bool
    requires_dist: list[Requirement] = field(default_factory=list)


Node = tuple[str, str]


class PipRelationshipVersionResolver:
    """Resolve direct and transitive dependencies using pip's dry-run report.

    Pip writes the resolved package metadata to a temporary JSON report. No
    packages are installed into the current environment. Resolution uses the
    current interpreter and available indexes, so it describes a fresh solution,
    not necessarily the versions installed or pinned elsewhere in the repository.
    One report and parent graph are reused for every target on this instance.
    """

    def __init__(
        self,
        requirements_text: str,
        *,
        requirements_path: str = "requirements.txt",
        support_files: Mapping[str, str] | None = None,
        timeout_seconds: int = 300,
    ) -> None:
        """Validate input paths and retain requirement/support files for staging."""
        if not requirements_text:
            raise ValueError("Requirements file content is required")
        path = PurePosixPath(requirements_path.replace("\\", "/"))
        if path.is_absolute() or ".." in path.parts:
            raise ValueError(f"Invalid requirements path: {requirements_path}")
        if path.suffix.lower() not in {".in", ".txt"}:
            raise ValueError("Pip resolution requires a .in or .txt requirements file")
        if timeout_seconds < 1:
            raise ValueError("timeout_seconds must be positive")
        self.requirements_text = requirements_text
        self.requirements_path = path.as_posix()
        self.support_files = {}
        for raw_path, text in (support_files or {}).items():
            support_path = PurePosixPath(raw_path.replace("\\", "/"))
            if support_path.is_absolute() or ".." in support_path.parts:
                raise ValueError(f"Invalid requirements support path: {raw_path}")
            self.support_files[support_path.as_posix()] = text
        self.timeout_seconds = timeout_seconds
        self._results: dict[str, dict] = {}
        self._packages: dict[Node, _Package] = {}
        self._by_name: dict[str, list[Node]] = defaultdict(list)
        self._parents: dict[Node, set[Node]] = defaultdict(set)
        self._loaded = False

    def prefetch(self, names: Iterable[str]) -> None:
        """Resolve metadata once and cache relationship results for the requested names."""
        targets = list(dict.fromkeys(names))
        if not targets:
            return
        if not self._loaded:
            self._load_report(self._run_report())
            self._build_parent_graph()
            self._loaded = True
        for name in targets:
            key = canonicalize_name(name)
            if key not in self._results:
                self._results[key] = self._resolve(key, name)

    def resolve(self, target: str) -> dict:
        """Return occurrences and root-to-target paths using normalized package names."""
        key = canonicalize_name(target)
        if key not in self._results:
            self.prefetch([target])
        return self._results[key]

    def _run_report(self) -> dict:
        """Stage inputs, run pip without installing, and validate its JSON report."""
        with tempfile.TemporaryDirectory(prefix="pip_relationship_") as tmp:
            directory = Path(tmp)
            for support_path, text in self.support_files.items():
                staged_support = directory.joinpath(*PurePosixPath(support_path).parts)
                staged_support.parent.mkdir(parents=True, exist_ok=True)
                staged_support.write_text(text, encoding="utf-8")
            requirements_file = directory.joinpath(*PurePosixPath(self.requirements_path).parts)
            requirements_file.parent.mkdir(parents=True, exist_ok=True)
            requirements_file.write_text(self.requirements_text, encoding="utf-8")
            report_path = directory / "report.json"
            # Dry-run resolves metadata into the report without installing packages.
            command = [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--dry-run",
                "--ignore-installed",
                "--report",
                str(report_path),
                "-r",
                self.requirements_path,
            ]
            result = subprocess.run(
                command,
                cwd=directory,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout_seconds,
                env=minimal_subprocess_env({"PIP_DISABLE_PIP_VERSION_CHECK": "1"}),
            )
            if result.returncode:
                logger.warning(
                    "pip dry run failed for %s (exit %s):\n%s\n%s",
                    self.requirements_path, result.returncode, result.stdout, result.stderr,
                )
                raise subprocess.CalledProcessError(
                    result.returncode,
                    command,
                    output=result.stdout,
                    stderr=result.stderr,
                )
            try:
                report = json.loads(report_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise ValueError("pip did not produce a valid JSON install report") from exc
            if not isinstance(report, dict) or not isinstance(report.get("install"), list):
                raise ValueError("Unexpected pip install report structure")
            return report

    def _load_report(self, report: dict) -> None:
        """Index report packages and parse valid Requires-Dist dependency declarations."""
        for item in report["install"]:
            metadata = item.get("metadata") if isinstance(item, dict) else None
            if not isinstance(metadata, dict):
                continue
            name, version = metadata.get("name"), metadata.get("version")
            if not isinstance(name, str) or not isinstance(version, str):
                continue
            requirements = []
            for raw_requirement in metadata.get("requires_dist") or []:
                if not isinstance(raw_requirement, str):
                    continue
                try:
                    requirements.append(Requirement(raw_requirement))
                except ValueError:
                    continue
            node = (canonicalize_name(name), version)
            self._packages[node] = _Package(
                name=name,
                version=version,
                requested=bool(item.get("requested")),
                requires_dist=requirements,
            )
            if node not in self._by_name[node[0]]:
                self._by_name[node[0]].append(node)

    def _direct_extras(self) -> dict[str, set[str]]:
        """Collect requested extras from supported requirement lines and local includes."""
        extras: dict[str, set[str]] = defaultdict(set)

        files = {**self.support_files, self.requirements_path: self.requirements_text}
        visited: set[str] = set()

        def visit(path: str) -> None:
            """Visit staged requirement includes once, preventing include cycles."""
            if path in visited or path not in files:
                return
            visited.add(path)
            parent = PurePosixPath(path).parent
            for raw_line in files[path].splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    tokens = shlex.split(line, comments=True)
                except ValueError:
                    continue
                if not tokens:
                    continue
                include = None
                if tokens[0] in {"-r", "--requirement"} and len(tokens) > 1:
                    include = tokens[1]
                elif tokens[0].startswith("--requirement="):
                    include = tokens[0].split("=", 1)[1]
                elif tokens[0].startswith("-r") and len(tokens[0]) > 2:
                    include = tokens[0][2:]
                if include is not None:
                    included = PurePosixPath(include.replace("\\", "/"))
                    if not included.is_absolute() and ".." not in included.parts:
                        visit((parent / included).as_posix())
                    continue
                if tokens[0].startswith("-") or tokens[0].startswith("."):
                    continue
                try:
                    clean = re.split(r"\s+#", line, maxsplit=1)[0]
                    requirement = Requirement(clean.split(" --hash=", 1)[0].strip())
                except ValueError:
                    continue
                if requirement.marker and not requirement.marker.evaluate():
                    continue
                extras[canonicalize_name(requirement.name)].update(requirement.extras)

        visit(self.requirements_path)
        return extras

    def _build_parent_graph(self) -> None:
        """Build child-to-parent edges, propagating extras until no new extras appear."""
        # The report marks direct requests; Requires-Dist metadata supplies parent edges.
        active_extras: dict[Node, set[str]] = defaultdict(set)
        direct_extras = self._direct_extras()
        for node, package in self._packages.items():
            if package.requested:
                active_extras[node].update(direct_extras.get(node[0], set()))

        environment = default_environment()
        changed = True
        while changed:
            changed = False
            for parent, package in self._packages.items():
                extras = active_extras[parent] | {""}
                for requirement in package.requires_dist:
                    # Keep only edges active for this interpreter and the parent's requested extras.
                    if requirement.marker and not any(
                        requirement.marker.evaluate({**environment, "extra": extra})
                        for extra in extras
                    ):
                        continue
                    child_name = canonicalize_name(requirement.name)
                    for child in self._by_name.get(child_name, []):
                        if not self._version_satisfies(requirement, self._packages[child].version):
                            continue
                        self._parents[child].add(parent)
                        new_extras = set(requirement.extras) - active_extras[child]
                        if new_extras:
                            active_extras[child].update(new_extras)
                            changed = True

    @staticmethod
    def _version_satisfies(requirement: Requirement, version: str) -> bool:
        """Check a resolved version against its parent requirement, allowing prereleases."""
        if not requirement.specifier:
            return True
        try:
            return requirement.specifier.contains(Version(version), prereleases=True)
        except InvalidVersion:
            return False

    def _resolve(self, target_key: str, target: str) -> dict:
        """Walk parent edges to direct requests, bounding cycles and path expansion."""
        target_nodes = self._by_name.get(target_key, [])
        occurrences = []
        for target_node in target_nodes:
            paths = []
            pending = [(target_node,)]
            expansions = 0
            while pending:
                reverse_path = pending.pop()
                expansions += 1
                if expansions > 100000:
                    raise ValueError("pip dependency path traversal limit exceeded")
                current = reverse_path[-1]
                if self._packages[current].requested:
                    path = list(reversed(reverse_path))
                    paths.append(path)
                    if len(paths) > 1000:
                        raise ValueError("pip dependency path count limit exceeded")
                for parent in sorted(self._parents.get(current, ()), reverse=True):
                    if parent not in reverse_path:
                        pending.append((*reverse_path, parent))

            def details(node: Node) -> dict[str, str]:
                """Render an indexed graph node as package identity for output paths."""
                package = self._packages[node]
                return {"package": package.name, "version": package.version}

            roots = {path[0]: details(path[0]) for path in paths}
            package = self._packages[target_node]
            occurrences.append({
                "package": package.name,
                "version": package.version,
                "introducers": [roots[node] for node in sorted(roots) if node != target_node],
                "is_root": package.requested,
                "paths": [[details(node) for node in path] for path in paths],
            })

        versions = {occurrence["version"] for occurrence in occurrences}
        return {
            "package": occurrences[0]["package"] if occurrences else target,
            "version": next(iter(versions)) if len(versions) == 1 else None,
            "occurrences": occurrences,
        }

