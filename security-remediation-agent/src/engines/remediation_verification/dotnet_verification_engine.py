"""NuGet resolution-only verification through `dotnet restore`."""
import json
import os
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from packaging.version import InvalidVersion, Version

from .verification_engine import ResolutionConflict, UnsupportedVerification, VerificationEngine, run

DOTNET_ECOSYSTEMS = frozenset({"nuget"})
PROJECT_SUFFIXES = frozenset({".csproj", ".fsproj", ".vbproj"})
# Downgrades and constraint violations are warnings by default; they mean the pins do not form a valid graph.
STRICT_WARNINGS = "-p:WarningsAsErrors=NU1605%3BNU1608"


def _local(tag):
    return tag.rsplit("}", 1)[-1]


class DotNetVerificationEngine(VerificationEngine):
    """Verify inline NuGet pins using an isolated dotnet restore.

    Core idea: replace selected references, reject downgrade/constraint warnings,
    and confirm the requested versions in project.assets.json. Central package
    versions without inline overrides require a richer snapshot and are unsupported."""
    @staticmethod
    def normalize_name(name):
        return name.casefold()

    def run_resolver(self, snapshot, project, targets):
        """Pin one project, restore with strict dependency warnings, and check the generated assets."""
        if len(targets) != 1:
            raise UnsupportedVerification("Multiple NuGet manifests require an explicit shared resolution input")
        manifest, upgrades = next(iter(targets.items()))
        if manifest.suffix.lower() not in PROJECT_SUFFIXES:
            raise UnsupportedVerification(
                f"NuGet verification needs a project file, not {manifest.name}")
        path = snapshot / manifest
        self._pin_project(path, upgrades)
        # A stale lock file would fail restore in locked mode once versions change.
        (snapshot / project / "packages.lock.json").unlink(missing_ok=True)
        try:
            run(["dotnet", "restore", manifest.name, "--nologo", "--verbosity", "minimal",
                 "-p:EnableWindowsTargeting=true", STRICT_WARNINGS], snapshot / project, self._env())
        except UnsupportedVerification:
            raise
        except ValueError as exc:
            named = self._named(str(exc), upgrades)
            if named:
                raise ResolutionConflict(named, str(exc)) from exc
            raise
        self._check_resolved(snapshot / project / "obj" / "project.assets.json", upgrades)

    @staticmethod
    def _env():
        # MSBuild/NuGet fail without ProgramFiles on Windows; none of these carry credentials.
        names = ("ProgramFiles", "ProgramFiles(x86)", "ProgramData", "ALLUSERSPROFILE", "DOTNET_ROOT")
        env = {name: os.environ[name] for name in names if name in os.environ}
        env.update({"DOTNET_CLI_TELEMETRY_OPTOUT": "1", "DOTNET_NOLOGO": "1"})
        return env

    @staticmethod
    def _pin_project(path, upgrades):
        text = path.read_text(encoding="utf-8-sig")
        try:
            root = ET.fromstring(text)
        except ET.ParseError as exc:
            raise ValueError(f"Invalid XML in {path.name}: {exc}") from exc
        namespace = root.tag[1:].split("}", 1)[0] if root.tag.startswith("{") else ""
        if namespace:
            ET.register_namespace("", namespace)
        pending = {name.casefold(): version for name, version in upgrades.items()}
        found = set()
        for node in root.iter():
            if _local(node.tag) != "PackageReference":
                continue
            name = (node.get("Include") or node.get("Update") or "").casefold()
            if name not in pending:
                continue
            version = pending[name]
            child = next((c for c in node if _local(c.tag) in {"VersionOverride", "Version"}), None)
            if node.get("VersionOverride") is not None:
                node.set("VersionOverride", version)
            elif node.get("Version") is not None:
                node.set("Version", version)
            elif child is not None:
                child.text = version
            else:
                raise UnsupportedVerification(
                    f"{name} has no inline version in {path.name}; "
                    "central package management (Directory.Packages.props) is not verified")
            found.add(name)
        missing = sorted(set(pending) - found)
        if missing:
            raise ValueError(f"Candidate is not declared in {path.name}: {', '.join(missing)}")
        ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)

    @staticmethod
    def _named(message, upgrades):
        """Pinned packages named on NuGet error or warning lines (NU1xxx)."""
        lines = [line for line in message.splitlines() if re.search(r"\bNU1\d{3}\b", line)]
        return {name for name in upgrades
                if any(re.search(rf"(?<![\w.-]){re.escape(name)}(?![\w.-])", line, re.I) for line in lines)}

    @staticmethod
    def _same_version(left, right):
        try:
            return Version(left) == Version(right)
        except InvalidVersion:
            return left.casefold() == right.casefold()

    def _check_resolved(self, assets, upgrades):
        if not assets.exists():
            raise ValueError("dotnet restore did not produce obj/project.assets.json")
        libraries = json.loads(assets.read_text(encoding="utf-8")).get("libraries", {})
        resolved = {}
        for key in libraries:
            name, _, version = key.partition("/")
            resolved.setdefault(name.casefold(), set()).add(version)
        unmet = {name: version for name, version in upgrades.items()
                 if not any(self._same_version(found, version) for found in resolved.get(name.casefold(), ()))}
        if unmet:
            raise ResolutionConflict(unmet, f"Resolved graph does not contain the requested pins: {unmet}")
