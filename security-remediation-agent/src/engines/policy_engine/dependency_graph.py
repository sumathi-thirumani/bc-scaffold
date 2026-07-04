from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class DependencyGraphNode:
    name: str
    version: str = ""
    ecosystem: str = ""
    manifest_path: str = ""
    lockfile_path: str = ""
    direct: bool = False
    dependencies: list[str] = field(default_factory=list)


@dataclass
class DependencyGraphResolution:
    package: str
    ecosystem: str = ""
    installed_version: str = ""
    manifest_path: str = ""
    lockfile_path: str = ""
    relationship: str = "unknown"
    dependency_paths: list[list[str]] = field(default_factory=list)
    nearest_declared_parent: str = ""
    remediation_target_dependency: str = ""
    graph_confidence: str = "unavailable"

    @property
    def dependency_path(self) -> list[str]:
        return self.dependency_paths[0] if self.dependency_paths else []


class DependencyGraph:
    def __init__(self, nodes: dict[str, DependencyGraphNode]) -> None:
        self.nodes = nodes

    @classmethod
    def from_npm_lockfile(
        cls,
        lockfile: dict[str, Any],
        *,
        manifest_path: str = "package.json",
        lockfile_path: str = "package-lock.json",
    ) -> DependencyGraph:
        if isinstance(lockfile.get("packages"), dict):
            return cls._from_package_lock_v2_or_v3(
                lockfile,
                manifest_path=manifest_path,
                lockfile_path=lockfile_path,
            )
        return cls._from_package_lock_v1(
            lockfile,
            manifest_path=manifest_path,
            lockfile_path=lockfile_path,
        )

    @classmethod
    def from_npm_lockfile_path(cls, lockfile_path: str | Path) -> DependencyGraph:
        path = Path(lockfile_path)
        return cls.from_npm_lockfile(
            json.loads(path.read_text(encoding="utf-8")),
            manifest_path=str(path.with_name("package.json")),
            lockfile_path=str(path),
        )

    @classmethod
    def _from_package_lock_v2_or_v3(
        cls,
        lockfile: dict[str, Any],
        *,
        manifest_path: str,
        lockfile_path: str,
    ) -> DependencyGraph:
        packages = lockfile.get("packages") or {}
        root = packages.get("") or {}
        declared = set((root.get("dependencies") or {}).keys())
        declared.update((root.get("devDependencies") or {}).keys())
        declared.update((root.get("optionalDependencies") or {}).keys())

        nodes: dict[str, DependencyGraphNode] = {}
        for path, payload in packages.items():
            if not path:
                continue
            name = payload.get("name") or cls._name_from_package_path(path)
            if not name:
                continue
            node = nodes.setdefault(
                name,
                DependencyGraphNode(
                    name=name,
                    ecosystem="npm",
                    manifest_path=manifest_path,
                    lockfile_path=lockfile_path,
                ),
            )
            node.version = node.version or str(payload.get("version") or "")
            node.direct = node.direct or name in declared
            node.dependencies.extend(
                dep for dep in (payload.get("dependencies") or {}).keys() if dep not in node.dependencies
            )

        return cls(nodes)

    @classmethod
    def _from_package_lock_v1(
        cls,
        lockfile: dict[str, Any],
        *,
        manifest_path: str,
        lockfile_path: str,
    ) -> DependencyGraph:
        nodes: dict[str, DependencyGraphNode] = {}

        def visit(name: str, payload: dict[str, Any], direct: bool) -> None:
            node = nodes.setdefault(
                name,
                DependencyGraphNode(
                    name=name,
                    ecosystem="npm",
                    manifest_path=manifest_path,
                    lockfile_path=lockfile_path,
                ),
            )
            node.version = node.version or str(payload.get("version") or "")
            node.direct = node.direct or direct
            for child_name, child_payload in (payload.get("dependencies") or {}).items():
                if child_name not in node.dependencies:
                    node.dependencies.append(child_name)
                visit(child_name, child_payload, False)

        for dep_name, dep_payload in (lockfile.get("dependencies") or {}).items():
            visit(dep_name, dep_payload, True)

        return cls(nodes)

    def resolve(self, package: str, ecosystem: str = "") -> DependencyGraphResolution:
        node = self.nodes.get(package)
        if not node:
            return DependencyGraphResolution(package=package, ecosystem=ecosystem)

        direct_roots = sorted(name for name, candidate in self.nodes.items() if candidate.direct)
        paths = self._paths_to(package, direct_roots)
        relationship = "direct" if node.direct else "transitive" if paths else "unknown"
        nearest_parent = package if relationship == "direct" else self._nearest_declared_parent(paths)

        return DependencyGraphResolution(
            package=package,
            ecosystem=node.ecosystem or ecosystem,
            installed_version=node.version,
            manifest_path=node.manifest_path,
            lockfile_path=node.lockfile_path,
            relationship=relationship,
            dependency_paths=paths,
            nearest_declared_parent=nearest_parent,
            remediation_target_dependency=package if relationship == "direct" else nearest_parent,
            graph_confidence="high" if relationship in {"direct", "transitive"} and nearest_parent else "low",
        )

    def _paths_to(self, package: str, roots: list[str]) -> list[list[str]]:
        paths: list[list[str]] = []
        for root in roots:
            self._walk(root, package, [root], set(), paths)
        return paths

    def _walk(
        self,
        current: str,
        target: str,
        path: list[str],
        seen: set[str],
        paths: list[list[str]],
    ) -> None:
        if current == target:
            paths.append(path.copy())
            return
        if current in seen:
            return
        seen.add(current)
        for child in self.nodes.get(current, DependencyGraphNode(current)).dependencies:
            self._walk(child, target, [*path, child], seen.copy(), paths)

    def _nearest_declared_parent(self, paths: list[list[str]]) -> str:
        for path in sorted(paths, key=len):
            if path:
                return path[0]
        return ""

    @staticmethod
    def _name_from_package_path(path: str) -> str:
        parts = path.split("node_modules/")
        if len(parts) < 2:
            return ""
        return parts[-1].rstrip("/")
