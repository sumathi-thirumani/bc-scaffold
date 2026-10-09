from __future__ import annotations

from collections import defaultdict
from typing import Any


class NpmResolver:
    DEP_FIELDS = (
        "dependencies",
        "devDependencies",
        "optionalDependencies",
    )

    def __init__(self, lock: dict[str, Any]):
        self.packages = lock.get("packages", {})

        if not self.packages:
            raise ValueError(
                "Expected package-lock.json v2/v3 with 'packages'"
            )

        self.by_name = defaultdict(list)
        self.parents = defaultdict(set)

        self._build_index()

    def resolve(self, target: str) -> dict:
        occurrences = []

        for location in sorted(self.by_name.get(target, [])):
            pkg = self.packages[location]
            occurrences.append({
                "package": target,
                "version": pkg.get("version"),
                # Return only actionable ancestors declared by the application.
                "introducers": self._find_introducers(location),
                "is_root": self._is_root_location(location),
            })

        return {
            "package": target,
            "occurrences": occurrences,
        }

    def _build_index(self) -> None:
        # Index package name -> locations
        for location in self.packages:
            if not location:
                continue

            name = self._package_name(location)
            self.by_name[name].append(location)

        # Build child -> parent reverse graph
        for parent_location, pkg in self.packages.items():
            for field in self.DEP_FIELDS:
                for child_name in pkg.get(field, {}):
                    child_location = self._resolve_child(
                        parent_location,
                        child_name,
                    )

                    if child_location:
                        self.parents[child_location].add(
                            parent_location
                        )

    def _find_introducers(self, location: str) -> list[dict]:
        """Return unique actionable ancestors declared in the root manifest."""
        result = {}
        visited = {location}
        stack = list(self.parents.get(location, ()))

        while stack:
            current = stack.pop()
            if not current or current in visited:
                continue
            visited.add(current)

            reference = self._package_reference(current)
            is_root = self._is_root_location(current)
            if is_root:
                key = (reference["package"], reference.get("version"))
                result[key] = reference
            stack.extend(self.parents.get(current, ()))

        return sorted(
            result.values(),
            key=lambda item: (
                item["package"],
                item.get("version") or "",
            ),
        )

    def _is_root_location(self, location: str) -> bool:
        return "" in self.parents.get(location, ())

    def _package_reference(self, location: str) -> dict:
        return {
            "package": self._package_name(location),
            "version": self.packages[location].get("version"),
        }

    def _resolve_child(
        self,
        parent_location: str,
        child_name: str,
    ) -> str | None:

        current = parent_location

        while True:
            candidate = (
                f"{current}/node_modules/{child_name}"
                if current
                else f"node_modules/{child_name}"
            )

            if candidate in self.packages:
                return candidate

            if not current:
                return None

            marker = "/node_modules/"

            current = (
                current.rsplit(marker, 1)[0]
                if marker in current
                else ""
            )

    def _package_name(
        self,
        location: str,
    ) -> str:

        pkg = self.packages[location]

        if name := pkg.get("name"):
            return name

        tail = location.rsplit(
            "node_modules/",
            1,
        )[-1]

        if tail.startswith("@"):
            scope, name, *_ = tail.split("/")
            return f"{scope}/{name}"

        return tail.split("/")[0]
