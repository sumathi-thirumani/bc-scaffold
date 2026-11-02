"""Resolution-only engines. Every command runs in a disposable repository snapshot."""
import json
import shutil
import subprocess
from pathlib import Path

from packaging.utils import canonicalize_name

from ...utils.subprocess_env import minimal_subprocess_env


class UnsupportedVerification(ValueError):
    pass


def run(args, cwd):
    executable = shutil.which(args[0])
    if executable is None:
        raise UnsupportedVerification(f"Required command is unavailable: {args[0]}")
    result = subprocess.run([executable, *args[1:]], cwd=cwd, capture_output=True,
                            text=True, encoding="utf-8", errors="replace", timeout=300,
                            env=minimal_subprocess_env({"NO_COLOR": "1"}))
    if result.returncode:
        raise ValueError(f"{args[0]} resolution failed (exit {result.returncode})")


class NpmVerificationEngine:
    family = "npm"

    @staticmethod
    def manifest(path):
        return Path(path).with_name("package.json")

    @staticmethod
    def project_root(snapshot, manifest):
        root = manifest.parent
        for parent in [root, *root.parents]:
            candidate = snapshot / parent / "package.json"
            if candidate.exists() and json.loads(candidate.read_text(encoding="utf-8")).get("workspaces"):
                root = parent
        return root

    def verify(self, snapshot, project, targets):
        for manifest, upgrades in targets.items():
            path = snapshot / manifest
            data = json.loads(path.read_text(encoding="utf-8"))
            if data.get("packageManager", "npm").split("@", 1)[0] != "npm":
                raise UnsupportedVerification("Only npm lockfile verification is supported for Node projects")
            for name, version in upgrades.items():
                found = False
                for field in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
                    for declared in data.get(field, {}):
                        if declared.casefold() == name.casefold():
                            data[field][declared] = version
                            found = True
                if not found:
                    raise ValueError(f"Candidate is not declared in {manifest}: {name}")
            path.write_text(json.dumps(data), encoding="utf-8")
        run(["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"], snapshot / project)
        lock = json.loads((snapshot / project / "package-lock.json").read_text(encoding="utf-8"))
        if lock.get("lockfileVersion", 0) < 2:
            raise UnsupportedVerification("Verification requires an npm v2/v3 lockfile")
        # Exact proposed pins are checked against the resolved graph, not command exit alone.
        resolved = lock.get("packages", {})
        for manifest, upgrades in targets.items():
            relative = manifest.parent.relative_to(project)
            for name, version in upgrades.items():
                parents = [relative, *relative.parents]
                paths = [(parent / "node_modules" / name).as_posix() for parent in parents]
                if not any(resolved.get(path, {}).get("version") == version for path in paths):
                    raise ValueError(f"Resolved graph does not contain the requested {name}=={version}")


class PythonVerificationEngine:
    family = "python"

    @staticmethod
    def manifest(path):
        path = Path(path)
        if path.name in {"uv.lock", "poetry.lock"}:
            return path.with_name("pyproject.toml")
        return path

    @staticmethod
    def project_root(snapshot, manifest):
        # Workspace resolution needs native uv lock handling; never certify a partial workspace.
        return manifest.parent

    def verify(self, snapshot, project, targets):
        import tomli
        if len(targets) != 1:
            raise UnsupportedVerification("Multiple Python manifests require an explicit shared resolution input")
        manifest, upgrades = next(iter(targets.items()))
        if manifest.name == "pyproject.toml":
            data = tomli.loads((snapshot / manifest).read_text(encoding="utf-8"))
            if "poetry" in data.get("tool", {}):
                raise UnsupportedVerification("Poetry verification requires a native lock engine")
            for parent in [project, *project.parents]:
                candidate = snapshot / parent / "pyproject.toml"
                if candidate.exists() and tomli.loads(candidate.read_text(encoding="utf-8")).get("tool", {}).get("uv", {}).get("workspace"):
                    raise UnsupportedVerification("uv workspace verification requires a native workspace lock engine")
        if manifest.suffix in {".txt", ".in"}:
            from packaging.requirements import InvalidRequirement, Requirement
            source = snapshot / manifest
            lines = []
            for line in source.read_text(encoding="utf-8").splitlines():
                try:
                    requirement = Requirement(line.split(" #", 1)[0].strip())
                except InvalidRequirement:
                    lines.append(line)
                    continue
                name = canonicalize_name(requirement.name)
                if name not in upgrades or requirement.url:
                    lines.append(line)
                    continue
                extras = "[" + ",".join(sorted(requirement.extras)) + "]" if requirement.extras else ""
                marker = f"; {requirement.marker}" if requirement.marker else ""
                lines.append(f"{requirement.name}{extras}=={upgrades[name]}{marker}")
            source.write_text("\n".join(lines) + "\n", encoding="utf-8")
        constraint = snapshot / project / ".remediation-constraints.txt"
        constraint.write_text("".join(f"{name}=={version}\n" for name, version in upgrades.items()), encoding="utf-8")
        output = snapshot / project / ".remediation-resolved.txt"
        # Proposed pins replace only selected requirements; other constraints remain in force.
        run(["uv", "pip", "compile", manifest.name, "--constraint", constraint.name,
             "--no-build", "--only-binary", ":all:", "--output-file", output.name], snapshot / project)
        from packaging.requirements import InvalidRequirement, Requirement
        resolved = {}
        for line in output.read_text(encoding="utf-8").splitlines():
            try:
                requirement = Requirement(line.strip())
            except InvalidRequirement:
                continue
            specs = list(requirement.specifier)
            if len(specs) == 1 and specs[0].operator == "==":
                resolved[canonicalize_name(requirement.name)] = specs[0].version
        for name, version in upgrades.items():
            if resolved.get(canonicalize_name(name)) != version:
                raise ValueError(f"Resolved graph does not contain the requested {name}=={version}")
