"""Resolve pip direct and transitive relationships from pip-compile output."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name


@dataclass
class _Package:
    name: str
    version: str | None
    requested: bool = False
    extras: tuple[str, ...] = ()
    requires: list[str] = field(default_factory=list)
    parents: list[str] = field(default_factory=list)


class PipRelationshipVersionResolver:
    """Resolve package relationships without invoking pip or contacting PyPI.

    The resolver accepts pip-compile output containing ``# via`` provenance,
    builds the graph once, and reuses it for every vulnerable package.
    """

    def __init__(self, text: str) -> None:
        packages = self._parse_compiled_text(text)
        if packages is None:
            raise ValueError("Requirements text has no pip-compile '# via' graph")
        self._packages = packages
        self._reverse = self._build_reverse_graph(packages)
        self._results: dict[str, dict] = {}

    @classmethod
    def from_compiled_text(cls, text: str) -> "PipRelationshipVersionResolver":
        return cls(text)

    def prefetch(self, names: Iterable[str]) -> None:
        """Resolve and cache a batch of vulnerable package names."""
        for name in dict.fromkeys(names):
            key = canonicalize_name(name)
            if key not in self._results:
                self._results[key] = self._resolve(key, name)

    def resolve(self, target: str) -> dict:
        key = canonicalize_name(target)
        if key not in self._results:
            self._results[key] = self._resolve(key, target)
        return self._results[key]

    def _resolve(self, target_key: str, target: str) -> dict:
        target_package = self._packages.get(target_key)
        if target_package is None:
            return {"package": target, "version": None, "introducers": []}

        paths = []
        roots = {}
        pending = [(target_key,)]
        expansions = 0
        while pending:
            reverse_path = pending.pop()
            expansions += 1
            if expansions > 100000 or len(paths) >= 1000:
                raise ValueError("pip dependency path traversal limit exceeded")
            current = reverse_path[-1]
            package = self._packages[current]
            if package.requested:
                roots[current] = {"package": package.name, "version": package.version}
                paths.append([
                    {"package": self._packages[key].name, "version": self._packages[key].version}
                    for key in reversed(reverse_path)
                ])
            # Continue past a declared root to capture alternate paths through it.
            for parent in sorted(self._reverse.get(current, ()), reverse=True):
                if parent not in reverse_path:
                    pending.append((*reverse_path, parent))
        return {
            "package": target_package.name,
            "version": target_package.version,
            "introducers": [roots[key] for key in sorted(roots)],
            "paths": paths,
        }

    @classmethod
    def _parse_compiled_text(cls, text: str) -> dict[str, _Package] | None:
        packages: dict[str, _Package] = {}
        current: _Package | None = None
        in_via = False
        has_via = False

        for raw_line in text.splitlines():
            stripped = raw_line.strip()
            if not stripped:
                current = None
                in_via = False
                continue

            if stripped.startswith("#"):
                if current is None:
                    continue
                comment = stripped[1:].strip()
                if comment == "via":
                    has_via = True
                    in_via = True
                    continue
                if comment.startswith("via "):
                    has_via = True
                    in_via = True
                    comment = comment[4:].strip()
                elif not in_via:
                    continue
                if not comment:
                    continue

                for source in (part.strip() for part in comment.split(",")):
                    if not source:
                        continue
                    if source.startswith(("-r ", "--requirement ")):
                        current.requested = True
                    elif not source.startswith(("-", "-c ", "--constraint ")):
                        parent = canonicalize_name(source)
                        if parent not in current.parents:
                            current.parents.append(parent)
                continue

            if stripped.startswith("--hash="):
                continue
            current = None
            in_via = False
            if stripped.startswith((
                "--hash=", "--", "-r ", "--requirement ", "-c ", "--constraint "
            )):
                continue
            try:
                requirement = Requirement(stripped.rstrip("\\").strip())
            except ValueError:
                continue

            pins = [
                specifier.version
                for specifier in requirement.specifier
                if specifier.operator in {"==", "==="}
            ]
            if len(pins) != 1:
                continue

            key = canonicalize_name(requirement.name)
            current = _Package(name=requirement.name, version=pins[0])
            packages[key] = current

        if not has_via:
            return None

        for child_key, child in packages.items():
            for parent_key in child.parents:
                parent = packages.get(parent_key)
                if parent is not None and child_key not in parent.requires:
                    parent.requires.append(child_key)
        return packages

    @classmethod
    def _build_reverse_graph(
        cls,
        packages: dict[str, _Package],
    ) -> dict[str, list[str]]:
        reverse: dict[str, list[str]] = {}
        for parent_key, parent in packages.items():
            for child_key in parent.requires:
                child = packages.get(child_key)
                if child is None:
                    continue
                reverse.setdefault(child_key, []).append(parent_key)
        return reverse

