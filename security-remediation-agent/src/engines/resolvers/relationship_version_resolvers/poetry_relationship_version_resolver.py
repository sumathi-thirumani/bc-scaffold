"""Offline declared-dependency paths from Poetry files; Python 3.10+.

Uses the tomli backport on Python 3.10. No subprocesses or network calls.
Reports all declared groups/extras, NOT a resolved environment-specific graph.
Conditional edges are retained. Duplicate locked names are rejected rather than
guessing which version/marker/source applies. No files are modified.
"""

import argparse
import json
import re
from pathlib import Path
import sys
from collections import defaultdict
from collections.abc import Iterable

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib


def normalize(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def read_toml(path):
    with path.open("rb") as file:
        return tomllib.load(file)


def direct_declarations(project):
    roots = {}

    def add(name, origin):
        match = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)", name)
        if not match:
            raise ValueError(f"Unsupported dependency declaration: {name!r}")
        roots.setdefault(normalize(match[1]), set()).add(origin)

    standard = project.get("project", {})
    if "dependencies" in standard.get("dynamic", []):
        raise ValueError("Dynamic project dependencies cannot be read statically.")
    for requirement in standard.get("dependencies", []):
        add(requirement, "project.dependencies")
    for group, requirements in standard.get("optional-dependencies", {}).items():
        for requirement in requirements:
            add(requirement, f"project.optional-dependencies.{group}")

    poetry = project.get("tool", {}).get("poetry", {})
    sections = [("tool.poetry.dependencies", poetry.get("dependencies", {})),
                ("tool.poetry.dev-dependencies", poetry.get("dev-dependencies", {}))]
    for group, data in poetry.get("group", {}).items():
        sections.append((f"tool.poetry.group.{group}", data.get("dependencies", {})))
    for origin, requirements in sections:
        for name in requirements:
            if normalize(name) != "python":
                add(name, origin)

    # PEP 735 groups can contain include-group entries: all groups are inspected,
    # so the included group's string dependencies are collected independently.
    for group, requirements in project.get("dependency-groups", {}).items():
        for requirement in requirements:
            if isinstance(requirement, str):
                add(requirement, f"dependency-groups.{group}")
    return roots


class PoetryRelationshipVersionResolver:
    """Resolve Poetry relationships from raw ``pyproject.toml`` and lock text."""

    def __init__(self, lock_text: str, project_text: str, *, max_paths: int = 1000):
        project = tomllib.loads(project_text)
        lock = tomllib.loads(lock_text)
        entries = lock.get("package")
        if not isinstance(entries, list):
            raise ValueError("Expected poetry.lock with [[package]] entries")

        self.max_paths = max_paths
        self.direct = set(direct_declarations(project))
        self.packages: dict[str, dict] = {}
        self.parents: dict[str, set[str]] = defaultdict(set)
        for entry in entries:
            key = normalize(entry["name"])
            if key in self.packages:
                raise ValueError(
                    f"Multiple lock entries for {key}; version/marker-aware resolution required."
                )
            self.packages[key] = entry

        for parent, entry in self.packages.items():
            for dependency in entry.get("dependencies", {}):
                child = normalize(dependency)
                if child in self.packages:
                    self.parents[child].add(parent)

        self._results: dict[str, dict] = {}

    def prefetch(self, names: Iterable[str]) -> None:
        for name in dict.fromkeys(names):
            key = normalize(name)
            if key not in self._results:
                self._results[key] = self._resolve(key, name)

    def resolve(self, target: str) -> dict:
        key = normalize(target)
        if key not in self._results:
            self._results[key] = self._resolve(key, target)
        return self._results[key]

    def _resolve(self, target_key: str, target: str) -> dict:
        package = self.packages.get(target_key)
        if package is None:
            return {"package": target, "occurrences": []}

        paths: list[list[str]] = []
        pending = [(target_key,)]
        expansions = 0
        while pending and len(paths) < self.max_paths and expansions < 100000:
            reverse_path = pending.pop()
            expansions += 1
            current = reverse_path[-1]
            if current in self.direct:
                paths.append(list(reversed(reverse_path)))
            for parent in sorted(self.parents.get(current, ()), reverse=True):
                if parent not in reverse_path:
                    pending.append((*reverse_path, parent))

        def details(name: str) -> dict[str, str]:
            entry = self.packages[name]
            return {"package": entry["name"], "version": entry["version"]}

        introducers = {
            path[0]: details(path[0])
            for path in paths
        }
        return {
            "package": package["name"],
            "occurrences": [{
                "package": package["name"],
                "version": package["version"],
                "introducers": [
                    introducers[key] for key in sorted(introducers)
                ],
                "is_root": target_key in self.direct,
                "paths": [[details(name) for name in path] for path in paths],
                "resolution_scope": "all locked groups and platforms",
            }],
        }


def inspect(project_dir, target, max_paths=1000):
    project = read_toml(project_dir / "pyproject.toml")
    lock = read_toml(project_dir / "poetry.lock")
    roots = direct_declarations(project)
    packages = {}
    for package in lock.get("package", []):
        key = normalize(package["name"])
        if key in packages:
            raise ValueError(f"Multiple lock entries for {key}; version/marker-aware resolution required.")
        packages[key] = package

    parents = {}
    missing = set()
    for parent, package in packages.items():
        for dependency in package.get("dependencies", {}):
            child = normalize(dependency)
            if child in packages:
                parents.setdefault(child, set()).add(parent)
            else:
                missing.add(child)

    key = normalize(target)
    paths = []
    pending = [(key,)] if key in packages else []
    expansions = 0
    truncated = False
    while pending:
        if len(paths) >= max_paths or expansions >= 100000:
            truncated = True
            break
        reverse_path = pending.pop()
        expansions += 1
        current = reverse_path[-1]
        if current in roots:
            paths.append(list(reversed(reverse_path)))
        # Continue beyond a direct node to retain alternate paths through roots.
        for parent in sorted(parents.get(current, ()), reverse=True):
            if parent not in reverse_path:
                pending.append((*reverse_path, parent))

    def details(name):
        package = packages[name]
        return {"package": package["name"], "version": package["version"]}

    package = packages.get(key)
    return {
        "package": package["name"] if package else target,
        "found": package is not None,
        "version": package["version"] if package else None,
        "direct": key in roots,
        "declared_in": sorted(roots.get(key, ())),
        "required_by": sorted(parents.get(key, ())),
        "introducers": [details(root) for root in sorted({path[0] for path in paths})],
        "paths": [[details(name) for name in path] for path in sorted(paths)],
        "paths_truncated": truncated,
        "dependency_declarations": package.get("dependencies", {}) if package else {},
        "analysis": "Declared lock graph across all groups/extras; markers are not evaluated.",
        "missing_locked_dependencies": sorted(missing),
        "limitations": [
            "Optional and conditional edges may be inactive in your environment.",
            "Lockfile freshness is not validated against the manifest.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", help="Target package, for example urllib3")
    parser.add_argument("--project", type=Path, default=Path.cwd())
    parser.add_argument("--max-paths", type=int, default=1000)
    args = parser.parse_args()
    if args.max_paths < 1:
        parser.error("--max-paths must be positive")
    try:
        result = inspect(args.project, args.package, args.max_paths)
    except (OSError, ValueError, KeyError) as error:
        print(json.dumps({"error": str(error)}), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
