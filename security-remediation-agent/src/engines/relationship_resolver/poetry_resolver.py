"""Find declared introducers across the dependency graph recorded by Poetry.

Includes all locked groups/platforms rather than selecting an installed environment.
"""
from collections import defaultdict

try:
    import tomllib
except ImportError:  # Python 3.10
    import tomli as tomllib

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name


class PoetryResolver:
    def __init__(self, lock_text: str, project_text: str):
        lock = tomllib.loads(lock_text)
        project = tomllib.loads(project_text)
        entries = lock.get("package")
        if not isinstance(entries, list):
            raise ValueError("Expected poetry.lock with [[package]] entries")
        self.packages = defaultdict(list)
        self.parents = defaultdict(set)
        self.direct = set()
        poetry = project.get("tool", {}).get("poetry", {})
        for table in [poetry.get("dependencies", {}), poetry.get("dev-dependencies", {}),
                      *(g.get("dependencies", {}) for g in poetry.get("group", {}).values())]:
            self.direct.update(canonicalize_name(name) for name in table if name.lower() != "python")
        pep621 = project.get("project", {})
        requirements = list(pep621.get("dependencies", []))
        for group in pep621.get("optional-dependencies", {}).values():
            requirements.extend(group)
        for group in project.get("dependency-groups", {}).values():
            requirements.extend(value for value in group if isinstance(value, str))
        self.direct.update(canonicalize_name(Requirement(value).name) for value in requirements)
        for entry in entries:
            name = canonicalize_name(entry["name"])
            self.packages[name].append(entry)
            for child in entry.get("dependencies", {}):
                self.parents[canonicalize_name(child)].add(name)

    def resolve(self, target: str) -> dict:
        target_key = canonicalize_name(target)
        visited = {target_key}
        stack = list(self.parents[target_key])
        introducers = {}
        while stack:
            name = stack.pop()
            if name in visited:
                continue
            visited.add(name)
            if name in self.direct:
                for package in self.packages[name]:
                    key = (package["name"], package["version"])
                    introducers[key] = {"package": key[0], "version": key[1]}
            else:
                stack.extend(self.parents[name])
        parents = [introducers[key] for key in sorted(introducers)]
        return {"package": target, "occurrences": [
            {"package": package["name"], "version": package["version"],
             "introducers": parents, "resolution_scope": "all locked groups and platforms"}
            for package in self.packages[target_key]
        ]}
