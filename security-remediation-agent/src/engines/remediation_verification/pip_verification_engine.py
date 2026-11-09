"""Python (pip/uv) resolution-only verification through `uv pip compile`."""
from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from .verification_engine import UnsupportedVerification, VerificationEngine, run

PYTHON_ECOSYSTEMS = frozenset({"pip", "pypi", "python", "poetry", "uv"})


class PythonVerificationEngine(VerificationEngine):
    """Verify Python pins with uv pip compile and joint constraints.

    Core idea: replace selected requirement specifiers, retain unrelated constraints,
    compile the graph, and confirm selected versions in the output. Native Poetry
    and uv workspace resolution are unsupported."""
    @staticmethod
    def normalize_name(name):
        return canonicalize_name(name)

    def run_resolver(self, snapshot, project, targets):
        """Compile one supported Python manifest with exact constraints and confirm selected versions."""
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
            self._pin_requirements(snapshot / manifest, upgrades)
        constraint = snapshot / project / ".remediation-constraints.txt"
        constraint.write_text("".join(f"{name}=={version}\n" for name, version in upgrades.items()), encoding="utf-8")
        output = snapshot / project / ".remediation-resolved.txt"
        # Proposed pins replace only selected requirements; other constraints remain in force.
        run(["uv", "pip", "compile", manifest.name, "--constraint", constraint.name,
             "--only-binary", ":all:", "--output-file", output.name], snapshot / project)
        resolved = self._resolved_versions(output)
        for name, version in upgrades.items():
            if resolved.get(canonicalize_name(name)) != version:
                raise ValueError(f"Resolved graph does not contain the requested {name}=={version}")

    @staticmethod
    def _pin_requirements(source, upgrades):
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

    @staticmethod
    def _resolved_versions(output):
        resolved = {}
        for line in output.read_text(encoding="utf-8").splitlines():
            try:
                requirement = Requirement(line.strip())
            except InvalidRequirement:
                continue
            specs = list(requirement.specifier)
            if len(specs) == 1 and specs[0].operator == "==":
                resolved[canonicalize_name(requirement.name)] = specs[0].version
        return resolved
