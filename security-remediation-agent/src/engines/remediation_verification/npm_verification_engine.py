"""npm lockfile-only resolution verification."""
import json
import re
import shutil
import tempfile
from pathlib import Path

from .verification_engine import ResolutionConflict, UnsupportedVerification, VerificationEngine, run

NPM_ECOSYSTEMS = frozenset({"npm", "npm_and_yarn"})


class BaselineResolutionError(UnsupportedVerification):
    """The original project cannot resolve under the supported peer policies."""


class NpmVerificationEngine(VerificationEngine):
    """Verify npm upgrade sets using temporary lockfile-only resolution.

    Core idea: resolve the untouched manifest to select strict or legacy peer rules,
    then reuse those rules for candidate attempts. Only baseline ERESOLVE triggers
    automatic legacy fallback. Successful npm exit determines success; the generated
    lockfile is not inspected, and legacy mode is disclosed in notes."""
    INSTALL = ["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"]

    def __init__(self):
        self._flags = None

    def verify(self, manifest_file, recommendations):
        """Reset policy state, run shared candidate verification, and record baseline or legacy-mode notes."""
        self._flags = None
        self._legacy_peer_deps = manifest_file.legacy_peer_deps
        manifest_file.baseline_failed = False
        manifest_file.verification_note = None
        try:
            result = super().verify(manifest_file, recommendations)
        except BaselineResolutionError as exc:
            manifest_file.baseline_failed = True
            manifest_file.verification_note = f"Baseline resolution failed for {manifest_file.path}: {exc}"
            raise
        if self._flags == ["--legacy-peer-deps"]:
            manifest_file.verification_note = (
                f"Verification of {manifest_file.path} used --legacy-peer-deps; peer compatibility was not checked."
            )
        return result

    @staticmethod
    def normalize_name(name):
        return name.casefold()

    def _baseline_flags(self, snapshot, project):
        """Resolve the untouched manifest once; fall back to --legacy-peer-deps if strict peers fail."""
        if self._flags is None:
            errors = []
            policies = (["--legacy-peer-deps"],) if getattr(self, "_legacy_peer_deps", False) else (["--legacy-peer-deps=false"], ["--legacy-peer-deps"])
            for flags in policies:
                with tempfile.TemporaryDirectory(prefix="npm_baseline_") as tmp:
                    copy = Path(tmp) / "project"
                    shutil.copytree(snapshot / project, copy)
                    try:
                        run([*self.INSTALL, *flags], copy)
                        self._flags = flags
                        break
                    except UnsupportedVerification:
                        raise
                    except ValueError as exc:
                        errors.append(f"{' '.join(flags)}: {exc}")
                        if "ERESOLVE" not in str(exc):
                            break
            if self._flags is None:
                raise BaselineResolutionError(
                    "The unmodified package.json does not resolve, so upgrades cannot be verified.\n"
                    + "\n".join(errors))
        return self._flags

    def run_resolver(self, snapshot, project, targets):
        """Select baseline flags, pin declared candidates, and require successful npm resolution."""
        flags = self._baseline_flags(snapshot, project)
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
        try:
            run([*self.INSTALL, *flags], snapshot / project)
        except UnsupportedVerification:
            raise
        except ValueError as exc:
            # ERESOLVE names the conflicting packages; report the pinned ones so they are not probed one by one.
            message = str(exc)
            named = {name for upgrades in targets.values() for name in upgrades
                     if "ERESOLVE" in message and re.search(rf"(?<![\w/.-]){re.escape(name)}@", message, re.I)}
            if "ERESOLVE" in message:
                # A conflict that names no pinned package already exists in the manifest; probing would repeat it.
                named = named or {name for upgrades in targets.values() for name in upgrades}
            if named:
                raise ResolutionConflict(named, message) from exc
            raise
