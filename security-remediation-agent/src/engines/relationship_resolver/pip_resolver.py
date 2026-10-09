import json
import subprocess
import sys

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

from ...utils.subprocess_env import minimal_subprocess_env


class PipResolver:
    def __init__(self, requirements_file: str):
        self.requirements_file = requirements_file
        self._report = None

    @classmethod
    def from_text(cls, text: str):
        """
        Resolve dependencies from requirements text.

        If `text` is pip-compile output containing `# via` comments, reconstruct
        the dependency graph directly from those comments.

        Otherwise, resolve ordinary PEP 508 requirements using
        `pip install --dry-run --report`.
        """
        compiled = cls._compiled_report(text)
        if compiled is not None:
            instance = cls("")
            instance._report = compiled
            return instance

        requirements = []

        for line in text.splitlines():
            line = line.split(" #", 1)[0].strip()

            if not line or line.startswith("#"):
                continue

            # Includes/options require project-aware handling.
            if line.startswith(("-r ", "--requirement ", "-c ", "--constraint ", "--")):
                raise ValueError(
                    "Requirement includes/options are not supported by from_text(); "
                    "use PipResolver(requirements_file) for project-aware resolution."
                )

            requirement = Requirement(line)

            if requirement.url:
                raise ValueError(
                    "Source URL requirements are not supported for parent resolution"
                )

            requirements.append(str(requirement))

        instance = cls("")

        if not requirements:
            instance._report = {"install": []}
            return instance

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--dry-run",
                "--ignore-installed",
                "--quiet",
                "--disable-pip-version-check",
                "--no-input",
                "--only-binary=:all:",
                "--report",
                "-",
                *requirements,
            ],
            capture_output=True,
            text=True,
            check=True,
            timeout=180,
            env=minimal_subprocess_env(),
        )

        instance._report = json.loads(result.stdout)
        return instance

    @staticmethod
    def _compiled_report(text: str):
        """
        Reconstruct a pip-style dependency report from pip-compile output.

        pip-compile semantics used here:

            fastapi==0.125.0
                # via
                #   -r requirements.in

        => fastapi is a DIRECT/root dependency.

            starlette==0.50.0
                # via
                #   fastapi
                #   fastapi-sqlalchemy

        => starlette is TRANSITIVE with immediate parents
           fastapi and fastapi-sqlalchemy.

        A package may be both explicitly requested and required by another
        package. For example:

            pydantic==1.10.26
                # via
                #   -r requirements.in
                #   fastapi

        Pydantic remains a direct/root dependency because `-r ...` is present.

        Constraint references (`-c` / `--constraint`) do NOT make a package
        direct and are not dependency parents.
        """
        entries = {}
        current = None
        in_via = False
        has_via = False

        for raw_line in text.splitlines():
            stripped = raw_line.strip()

            # Blank lines end the current requirement/comment block.
            if not stripped:
                current = None
                in_via = False
                continue

            # ----------------------------------------------------------
            # Comments
            # ----------------------------------------------------------
            if stripped.startswith("#"):
                if current is None:
                    continue

                comment = stripped[1:].strip()

                # Start of a multiline block:
                #
                #   # via
                #   #   fastapi
                if comment == "via":
                    has_via = True
                    in_via = True
                    continue

                # Single-line form:
                #
                #   # via fastapi
                if comment.startswith("via "):
                    has_via = True
                    in_via = True
                    comment = comment[4:].strip()
                elif not in_via:
                    # Other generated comments do not describe parents.
                    continue

                if not comment:
                    continue

                # pip-compile commonly emits one source per line, but handling
                # comma-separated sources costs nothing and keeps this robust.
                sources = [
                    source.strip()
                    for source in comment.split(",")
                    if source.strip()
                ]

                for source in sources:
                    # Explicit requirements-file provenance means this package
                    # is a direct/root dependency.
                    if source.startswith(("-r ", "--requirement ")):
                        entries[current]["requested"] = True
                        continue

                    # Constraints influence versions only; they do not make the
                    # package direct and are not dependency parents.
                    if source.startswith(("-c ", "--constraint ")):
                        continue

                    # Ignore other pip options/directives.
                    if source.startswith("-"):
                        continue

                    parent = canonicalize_name(source)

                    if parent not in entries[current]["parents"]:
                        entries[current]["parents"].append(parent)

                continue

            # ----------------------------------------------------------
            # Requirement/pin line
            # ----------------------------------------------------------
            in_via = False
            current = None

            # Ignore global pip options and include directives.
            if stripped.startswith(
                ("--hash=", "--", "-r ", "--requirement ", "-c ", "--constraint ")
            ):
                continue

            requirement_text = stripped.rstrip("\\").strip()

            try:
                requirement = Requirement(requirement_text)
            except ValueError:
                continue

            pins = [
                specifier.version
                for specifier in requirement.specifier
                if specifier.operator in {"==", "==="}
            ]

            # This parser intentionally handles pip-compile's fully pinned
            # requirements only.
            if len(pins) != 1:
                continue

            current = canonicalize_name(requirement.name)

            entries[current] = {
                "requested": False,
                "parents": [],
                "metadata": {
                    "name": requirement.name,
                    "version": pins[0],
                    "requires_dist": [],
                },
            }

        if not has_via:
            return None

        # Convert child -> parents from `# via` into parent -> requires_dist so
        # the same introducer traversal works for pip reports and compiled text.
        for child, entry in entries.items():
            for parent in entry["parents"]:
                parent_entry = entries.get(parent)

                if parent_entry is None:
                    continue

                requires = parent_entry["metadata"]["requires_dist"]

                if child not in requires:
                    requires.append(child)

        return {"install": list(entries.values())}

    def resolve(self, target: str) -> dict:
        """
        Resolve `target` and return only actionable ROOT introducers.

        Direct target:
            requirements.in -> starlette
            => introducer = starlette

        Transitive target:
            requirements.in -> fastapi -> starlette
            => introducer = fastapi
        """
        if self._report is not None:
            return self._find_introducers(self._report, target)

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--dry-run",
                "--ignore-installed",
                "--quiet",
                "--disable-pip-version-check",
                "--no-input",
                "--only-binary=:all:",
                "--report",
                "-",
                "-r",
                self.requirements_file,
            ],
            capture_output=True,
            text=True,
            check=True,
            timeout=180,
            env=minimal_subprocess_env(),
        )

        self._report = json.loads(result.stdout)
        return self._find_introducers(self._report, target)

    def _find_introducers(self, report: dict, target: str) -> dict:
        """
        Find actionable root introducers.

        Rules:
        1. `requested=True` means direct/root.
        2. If the target itself is direct, return the target as its introducer.
        3. Otherwise traverse immediate parents upward until direct/root
           dependencies are reached.
        4. Return only those roots; do not return intermediate transitives.
        """
        packages = {}

        for item in report.get("install", []):
            metadata = item.get("metadata", {})
            name = metadata.get("name")

            if not name:
                continue

            key = canonicalize_name(name)

            packages[key] = {
                "name": name,
                "version": metadata.get("version"),
                "requires": metadata.get("requires_dist", []) or [],
                "requested": bool(item.get("requested", False)),
                "extras": item.get("requested_extras", []) or [],
            }

        # Build reverse graph: child -> immediate parents.
        reverse = {}

        for parent_key, parent in packages.items():
            for req_text in parent["requires"]:
                try:
                    req = Requirement(req_text)

                    if req.marker:
                        extras = ["", *parent["extras"]]

                        if not any(
                            req.marker.evaluate({"extra": extra})
                            for extra in extras
                        ):
                            continue
                except Exception:
                    # A malformed metadata requirement should not prevent
                    # analysis of the remainder of the graph.
                    continue

                child_key = canonicalize_name(req.name)
                parents = reverse.setdefault(child_key, [])

                if parent_key not in parents:
                    parents.append(parent_key)

        target_key = canonicalize_name(target)
        target_pkg = packages.get(target_key)

        if target_pkg is None:
            return {
                "package": target,
                "version": None,
                "introducers": [],
            }

        # A directly declared vulnerable package is itself the actionable root,
        # even when another package also depends on it (e.g. Pydantic).
        if target_pkg["requested"]:
            return {
                "package": target_pkg["name"],
                "version": target_pkg["version"],
                "introducers": [
                    {
                        "package": target_pkg["name"],
                        "version": target_pkg["version"],
                    }
                ],
            }

        introducers = {}
        visited = set()

        def walk(name: str):
            if name in visited:
                return

            visited.add(name)

            for parent_key in reverse.get(name, []):
                parent = packages.get(parent_key)

                if parent is None:
                    continue

                if parent["requested"]:
                    introducers[parent_key] = {
                        "package": parent["name"],
                        "version": parent["version"],
                    }
                else:
                    walk(parent_key)

        walk(target_key)

        # Sort for deterministic output/tests.
        ordered_introducers = [
            introducers[key]
            for key in sorted(introducers)
        ]

        return {
            "package": target_pkg["name"],
            "version": target_pkg["version"],
            "introducers": ordered_introducers,
        }
