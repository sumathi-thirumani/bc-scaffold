"""Resolve NuGet dependency paths with the .NET package-list and why commands."""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
from collections.abc import Iterable, Mapping
from pathlib import Path, PurePosixPath
from typing import Any

from ....utils.subprocess_env import minimal_subprocess_env

logger = logging.getLogger(__name__)

# Restore evaluates repository MSBuild/NuGet files, so only variables the SDK needs
# are passed; tokens such as GITHUB_TOKEN never reach it. NuGet feed credentials
# (NUGET_*, NuGetPackageSourceCredentials_*) are passed so private feeds still work.
_PASSTHROUGH_ENV = re.compile(
    r"^(nuget|dotnet|msbuild|programfiles|programdata|programw6432)", re.IGNORECASE
)
MAX_PATHS_PER_TARGET = 1000
MAX_EXPANSIONS = 100000
MAX_LOGGED_OUTPUT_LINES = 40


class NuGetRelationshipVersionResolver:
    """Find transitive NuGet packages from restored ``project.assets.json`` graphs.

    The resolver stages each project and its NuGet/MSBuild configuration, runs
    ``dotnet restore``, then walks the restored target dependency edges to direct roots.
    Pass ``repository_root`` to use a complete checkout instead of staging files;
    restore may generate normal NuGet/MSBuild output files in that checkout.
    """

    def __init__(
        self,
        project_files: Mapping[str, str],
        *,
        support_files: Mapping[str, str] | None = None,
        dotnet_executable: str | None = None,
        timeout_seconds: int = 300,
        total_timeout_seconds: int = 1800,
        repository_root: str | Path | None = None,
    ) -> None:
        if not project_files:
            raise ValueError("At least one .csproj file is required for NuGet resolution")
        self.project_files = self._normalize_files(project_files)
        self.support_files = self._normalize_files(support_files or {})
        self.dotnet = dotnet_executable or shutil.which("dotnet")
        if not self.dotnet:
            raise OSError("dotnet executable not found")
        if timeout_seconds < 1 or total_timeout_seconds < 1:
            raise ValueError("timeouts must be positive")
        self.timeout_seconds = timeout_seconds
        self.total_timeout_seconds = total_timeout_seconds
        self._deadline = float("inf")
        self.repository_root = Path(repository_root).resolve() if repository_root is not None else None
        if self.repository_root is not None and not self.repository_root.is_dir():
            raise ValueError(f"Repository directory does not exist: {self.repository_root}")
        self._results: dict[str, dict[str, Any]] = {}
        # Restored graphs and failures are kept per project so a later target never
        # repeats a restore, and a failing project is not retried by every lookup.
        self._graphs: dict[str, list[dict[str, Any]]] = {}
        self._project_errors: dict[str, str] = {}

    @staticmethod
    def _normalize_files(files: Mapping[str, str]) -> dict[str, str]:
        normalized = {}
        for raw_path, text in files.items():
            path = PurePosixPath(raw_path.replace("\\", "/"))
            # A "C:" part would switch drives when joined on Windows.
            if path.is_absolute() or ".." in path.parts or any(":" in part for part in path.parts):
                raise ValueError(f"Invalid repository path: {raw_path}")
            normalized[path.as_posix()] = text
        return normalized

    def prefetch(self, names: Iterable[str]) -> None:
        targets = list(dict.fromkeys(names))
        missing = [target for target in targets if target.casefold() not in self._results]
        if not missing:
            return

        pending = [
            project for project in self.project_files
            if project not in self._graphs and project not in self._project_errors
        ]
        if pending:
            self._restore_projects(pending)

        failures = [
            {"project": project, "error": error}
            for project, error in self._project_errors.items()
        ]
        for target in missing:
            key = target.casefold()
            occurrences: dict[tuple[str, str, str], dict[str, Any]] = {}
            for project_path, graphs in self._graphs.items():
                for graph in graphs:
                    package = graph["nodes"].get(key)
                    if package is None:
                        continue
                    paths, truncated = self._root_paths(
                        key, graph["nodes"], graph["parents"], graph["direct"]
                    )
                    self._add_occurrence(
                        occurrences,
                        project_path,
                        graph["framework"],
                        package["name"],
                        package["version"],
                        is_root=key in graph["direct"],
                        paths=paths,
                        truncated=truncated,
                    )
            self._results[key] = {
                "package": target,
                "occurrences": list(occurrences.values()),
                "complete": not failures,
                "errors": list(failures),
            }

    def _restore_projects(self, pending: list[str]) -> None:
        self._deadline = time.monotonic() + self.total_timeout_seconds
        with tempfile.TemporaryDirectory(prefix="nuget_relationship_") as tmp:
            root = self.repository_root or Path(tmp)
            if self.repository_root is None:
                self._stage_files(root, self.support_files)
                self._stage_files(root, self.project_files)
            logger.info(
                "NuGet resolution workspace=%s mode=%s projects=%s support_files=%s",
                root, "repository" if self.repository_root else "staged",
                len(self.project_files), len(self.support_files),
            )
            logger.debug("NuGet project paths: %s", sorted(self.project_files))
            logger.debug("NuGet support paths: %s", sorted(self.support_files))
            try:
                sdk_version = self._run(root, ["--version"]).strip()
                logger.info("NuGet resolver SDK=%s executable=%s", sdk_version, self.dotnet)
            except (OSError, subprocess.SubprocessError) as exc:
                logger.warning("Cannot select .NET SDK: %s", self._format_command_error(exc))
                raise

            for project_path in pending:
                project_file = root.joinpath(*PurePosixPath(project_path).parts)
                if not project_file.is_file():
                    logger.warning("NuGet project file was not staged: %s", project_path)
                    self._project_errors[project_path] = "Project file is missing"
                    continue
                self._log_project_context(root, project_file)
                try:
                    assets = self._restore_assets(root, project_path)
                    self._graphs[project_path] = self._load_graphs(assets, project_path)
                except (OSError, ValueError, subprocess.SubprocessError) as exc:
                    logger.warning(
                        "Cannot restore NuGet project %s: %s",
                        project_path, self._format_command_error(exc),
                    )
                    self._project_errors[project_path] = self._format_command_error(exc)

    def resolve(self, target: str, project_path: str | None = None) -> dict[str, Any]:
        key = target.casefold()
        if key not in self._results:
            self.prefetch([target])
        result = self._results[key]
        if project_path is None:
            return result
        normalized_path = PurePosixPath(project_path.replace("\\", "/")).as_posix()
        occurrences = [
            occurrence for occurrence in result["occurrences"]
            if occurrence["manifest_path"] == normalized_path
        ]
        versions = {occurrence.get("version") for occurrence in occurrences}
        version = next(iter(versions)) if len(versions) == 1 and None not in versions else None
        frameworks = {occurrence["framework"] for occurrence in occurrences}
        paths = []
        seen_paths = set()
        for occurrence in occurrences:
            for packages in occurrence["paths"]:
                path_key = (
                    occurrence["framework"],
                    tuple((package["package"], package["version"]) for package in packages),
                )
                if path_key in seen_paths:
                    continue
                seen_paths.add(path_key)
                paths.append({
                    "directIntroducer": packages[0]["package"] if len(packages) > 1 else None,
                    "immediateIntroducer": packages[-2]["package"] if len(packages) > 1 else None,
                    "packages": [
                        {"name": package["package"], "version": package["version"]}
                        for package in packages
                    ],
                })
        return {
            "project": PurePosixPath(normalized_path).stem,
            "framework": next(iter(frameworks)) if len(frameworks) == 1 else None,
            "target": target,
            "paths": paths,
            "paths_truncated": any(
                occurrence.get("paths_truncated") for occurrence in occurrences
            ),
            "package": target,
            "version": version,
            "occurrences": occurrences,
            "complete": not any(error["project"] == normalized_path for error in result["errors"]),
            "errors": [error for error in result["errors"] if error["project"] == normalized_path],
        }

    @staticmethod
    def _stage_files(root: Path, files: Mapping[str, str]) -> None:
        for raw_path, text in files.items():
            path = root.joinpath(*PurePosixPath(raw_path).parts)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")

    def _restore_assets(self, root: Path, project_path: str) -> dict[str, Any]:
        project_file = root.joinpath(*PurePosixPath(project_path).parts)
        if not project_file.is_file():
            raise ValueError(f"Project file was not staged: {project_path}")
        self._run(root, ["restore", project_path, "--nologo", "--verbosity", "minimal"])
        assets_path = project_file.parent / "obj" / "project.assets.json"
        try:
            assets = json.loads(assets_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"Cannot read restore assets for {project_path}") from exc
        if not isinstance(assets, dict):
            raise ValueError(f"Unexpected restore assets for {project_path}")
        return assets

    def _run(self, root: Path, arguments: list[str]) -> str:
        command = [self.dotnet, *arguments]
        environment = minimal_subprocess_env({
            "NO_COLOR": "1", "DOTNET_NOLOGO": "1",
            "DOTNET_CLI_UI_LANGUAGE": "en-US",
            "DOTNET_CLI_FORCE_UTF8_ENCODING": "1",
        })
        environment.update({
            name: value for name, value in os.environ.items()
            if _PASSTHROUGH_ENV.match(name) and name not in environment
        })
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(command, self.total_timeout_seconds)
        timeout = min(self.timeout_seconds, remaining)
        logger.info("Running NuGet command=%s cwd=%s timeout=%.0fs", command, root, timeout)
        started = time.monotonic()
        try:
            result = subprocess.run(
                command, cwd=root, capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=timeout,
                env=environment,
            )
        except subprocess.TimeoutExpired as exc:
            self._log_command_output("stdout", exc.stdout, logging.WARNING)
            self._log_command_output("stderr", exc.stderr, logging.WARNING)
            logger.warning("NuGet command timed out after %.2fs: %s", time.monotonic() - started, command)
            raise
        logger.info(
            "NuGet command finished exit_code=%s elapsed=%.2fs",
            result.returncode, time.monotonic() - started,
        )
        output_level = logging.WARNING if result.returncode else logging.DEBUG
        self._log_command_output("stdout", result.stdout, output_level)
        self._log_command_output("stderr", result.stderr, output_level)
        if result.returncode:
            logger.warning("NuGet command failed cwd=%s command=%s", root, command)
            raise subprocess.CalledProcessError(
                result.returncode, command, output=result.stdout, stderr=result.stderr
            )
        return result.stdout

    @staticmethod
    def _log_command_output(stream: str, output: str | bytes | None, level: int) -> None:
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        # A separate log record per line survives handlers that truncate multiline messages.
        lines = output.splitlines() if output else []
        if not lines:
            logger.log(level, "dotnet %s: <empty>", stream)
        for line in lines[:MAX_LOGGED_OUTPUT_LINES]:
            logger.log(level, "dotnet %s: %s", stream, line)
        if len(lines) > MAX_LOGGED_OUTPUT_LINES:
            logger.log(
                level, "dotnet %s: ... %d more lines omitted",
                stream, len(lines) - MAX_LOGGED_OUTPUT_LINES,
            )

    @staticmethod
    def _log_project_context(root: Path, project_file: Path) -> None:
        logger.info("Inspecting NuGet project=%s", project_file)
        try:
            document = ET.parse(project_file)
        except (OSError, ET.ParseError) as exc:
            logger.warning("Cannot inspect project XML %s: %s", project_file, exc)
            return
        for element in document.iter():
            tag = element.tag.rsplit("}", 1)[-1]
            if tag not in {"ProjectReference", "Import"}:
                continue
            value = element.get("Include" if tag == "ProjectReference" else "Project")
            if not value:
                continue
            for reference in value.split(";"):
                if any(token in reference for token in ("$(", "@(", "%(", "*", "?")):
                    logger.debug("MSBuild will evaluate %s=%s", tag, reference)
                    continue
                candidate = (project_file.parent / reference.replace("\\", "/")).resolve()
                if not candidate.is_file():
                    logger.warning(
                        "Missing %s for %s: %s (evaluated conditions may exclude it). "
                        "Supply the referenced file or set repository_root to the complete checkout.",
                        tag, project_file.relative_to(root), candidate,
                    )
        versionless = [
            element.get("Include", element.get("Update", ""))
            for element in document.iter()
            if element.tag.rsplit("}", 1)[-1] == "PackageReference"
            and not element.get("Version") and not element.get("VersionOverride")
            and not any(child.tag.rsplit("}", 1)[-1] in {"Version", "VersionOverride"} for child in element)
        ]
        if versionless:
            logger.debug("Package references with externally supplied or implicit versions: %s", versionless)

    @staticmethod
    def _format_command_error(exc: BaseException) -> str:
        """Include captured CLI diagnostics instead of only its exit status."""
        if not isinstance(exc, (subprocess.CalledProcessError, subprocess.TimeoutExpired)):
            return str(exc)

        details = [str(exc)]
        for label, output in (("STDOUT", exc.stdout), ("STDERR", exc.stderr)):
            if isinstance(output, bytes):
                output = output.decode("utf-8", errors="replace")
            if output and output.strip():
                details.append(f"{label}:\n{output.strip()}")
        return "\n".join(details)

    @staticmethod
    def _framework_identity(name: str) -> tuple[str, str] | None:
        """Return (family, version digits) for a target name or a TFM alias."""
        target = re.match(r"\.?([A-Za-z]+),Version=v?(\d[\d.]*)", name)
        if target:
            return target[1].casefold(), target[2].replace(".", "")
        alias = re.match(r"([A-Za-z]+)(\d[\d.]*)", name)
        if not alias:
            return None
        prefix, version = alias[1].casefold(), alias[2]
        if prefix == "net":
            # net5.0+ is .NETCoreApp; netNN/netNNN (net48) is .NET Framework.
            family = "netcoreapp" if "." in version else "netframework"
        else:
            family = prefix
        return family, version.replace(".", "")

    @staticmethod
    def _framework_details(
        target_name: str,
        project_frameworks: Mapping[str, Any],
    ) -> tuple[str, dict[str, Any]]:
        target_identity = NuGetRelationshipVersionResolver._framework_identity(target_name)
        candidates = []
        for name, metadata in project_frameworks.items():
            if not isinstance(metadata, dict):
                continue
            alias = str(metadata.get("targetAlias", name))
            if target_name.casefold() in {str(name).casefold(), alias.casefold()}:
                return alias, metadata
            if (
                target_identity
                and target_identity == NuGetRelationshipVersionResolver._framework_identity(alias)
            ):
                candidates.append((alias, metadata))
        if len(candidates) == 1:
            return candidates[0]
        if len(project_frameworks) == 1:
            name, metadata = next(iter(project_frameworks.items()))
            if isinstance(metadata, dict):
                return str(metadata.get("targetAlias", name)), metadata
        return target_name, {}

    @staticmethod
    def _assets_nodes(target_data: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
        nodes = {}
        for package_key, metadata in target_data.items():
            if not isinstance(package_key, str) or "/" not in package_key:
                continue
            name, version = package_key.rsplit("/", 1)
            if not isinstance(metadata, dict) or metadata.get("type", "package") not in {
                "package", "project",
            }:
                continue
            nodes[name.casefold()] = {
                "name": name,
                "version": version,
                "dependencies": metadata.get("dependencies", {}),
            }
        return nodes

    def _load_graphs(self, assets: dict[str, Any], project_path: str) -> list[dict[str, Any]]:
        asset_targets = assets.get("targets")
        project = assets.get("project", {})
        project_frameworks = project.get("frameworks", {}) if isinstance(project, dict) else {}
        if not isinstance(asset_targets, dict) or not isinstance(project_frameworks, dict):
            raise ValueError(f"Restore assets have no targets/frameworks for {project_path}")

        graphs = []
        for target_name, target_data in asset_targets.items():
            if not isinstance(target_data, dict):
                continue
            framework_name, framework_metadata = self._framework_details(
                target_name, project_frameworks
            )
            nodes = self._assets_nodes(target_data)
            declarations = framework_metadata.get("dependencies", {})
            direct_names = {
                name.casefold()
                for name, details in declarations.items()
                if isinstance(name, str)
                and (
                    not isinstance(details, dict)
                    or str(details.get("target", "Package")).casefold() in {"package", "project"}
                )
            } if isinstance(declarations, dict) else set()

            parents: dict[str, set[str]] = {}
            for parent_name, package in nodes.items():
                dependencies = package["dependencies"]
                if not isinstance(dependencies, dict):
                    continue
                for child_name in dependencies:
                    child_key = str(child_name).casefold()
                    if child_key in nodes:
                        parents.setdefault(child_key, set()).add(parent_name)
            graphs.append({
                "framework": framework_name,
                "nodes": nodes,
                "parents": parents,
                "direct": direct_names,
            })
        return graphs

    @staticmethod
    def _root_paths(
        target: str,
        nodes: Mapping[str, dict[str, Any]],
        parents: Mapping[str, set[str]],
        direct_names: set[str],
    ) -> tuple[list[list[dict[str, str]]], bool]:
        """Return root-to-target paths and whether a limit stopped the search early."""
        paths = []
        pending = [(target,)]
        expansions = 0
        truncated = False
        while pending:
            reverse_path = pending.pop()
            expansions += 1
            if expansions > MAX_EXPANSIONS:
                truncated = True
                break
            current = reverse_path[-1]
            if current in direct_names:
                paths.append([
                    {"package": nodes[name]["name"], "version": nodes[name]["version"]}
                    for name in reversed(reverse_path)
                ])
                if len(paths) >= MAX_PATHS_PER_TARGET:
                    truncated = bool(pending)
                    break
            for parent in sorted(parents.get(current, ()), reverse=True):
                if parent not in reverse_path:
                    pending.append((*reverse_path, parent))
        return paths, truncated

    @staticmethod
    def _add_occurrence(
        occurrences: dict[tuple[str, str, str], dict[str, Any]],
        project_path: str,
        framework: str,
        package: str,
        version: str | None,
        *,
        is_root: bool,
        paths: list[list[dict[str, str]]],
        truncated: bool = False,
    ) -> None:
        key = (project_path, framework, version or "")
        occurrence = occurrences.setdefault(
            key,
            {
                "package": package,
                "version": version,
                "introducers": [],
                "is_root": False,
                "paths": [],
                "paths_truncated": False,
                "manifest_path": project_path,
                "framework": framework,
            },
        )
        occurrence["is_root"] = occurrence["is_root"] or is_root
        occurrence["paths_truncated"] = occurrence["paths_truncated"] or truncated
        for path in paths:
            if len(path) > 1 and path[0] not in occurrence["introducers"]:
                occurrence["introducers"].append(path[0])
            if path not in occurrence["paths"]:
                occurrence["paths"].append(path)
