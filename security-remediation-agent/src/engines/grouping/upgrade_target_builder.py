"""Consolidate triaged findings into per-manifest upgrade targets with verification results."""
from pathlib import PurePosixPath

from packaging.version import InvalidVersion, Version

from ...models.security_package_triage import SecurityPackageTriage

# Verification messages caused by the runner/environment rather than a real incompatibility.
ENVIRONMENT_MESSAGES = ("Required command is unavailable", "Verification timed out", "Manifest unavailable",
                        "Verification unsupported:")


class UpgradeTargetBuilder:
    """Build upgrade targets from a bundle's packages; run after verification so results are included."""

    @staticmethod
    def build(packages: list[SecurityPackageTriage]) -> list[dict]:
        grouped = {}
        for package in packages:
            manifest_path = (
                PurePosixPath(package.manifest_path.replace("\\", "/").lstrip("/")).as_posix()
                if package.manifest_path else None
            )
            entries = [
                {"package": recommendation.package, "current_version": recommendation.from_version,
                 "minimum_fixed_version": recommendation.minimum_patched_version,
                 "compatible_version": package.compatible_version(recommendation.package),
                 "review_status": recommendation.compatible_review_status,
                 "allow_prerelease": recommendation.allow_prerelease,
                 "highest_fixed_version": recommendation.highest_stable_version,
                 "qualifying_versions": [c.version for c in recommendation.qualifying_upgrade_versions]}
                for recommendation in package.package_upgrade_recommendations
            ]
            if not entries and not package.istransitive:
                entries = [{"package": package.package, "current_version": package.current_version,
                            "minimum_fixed_version": package.vulnerablility_fixed_version,
                            "compatible_version": "", "highest_fixed_version": "",
                            "qualifying_versions": None}]
            if not entries:
                entries = [
                    {"package": parent.package, "current_version": parent.version,
                     "minimum_fixed_version": "", "compatible_version": "",
                     "highest_fixed_version": "", "qualifying_versions": []}
                    for occurrence in package.transitive_dependency_occurrences
                    for parent in occurrence.introducers
                ]
            for entry in entries:
                entry.setdefault("allow_prerelease", False)
                entry.setdefault("review_status", None)
                entry["manifest_path"] = manifest_path
                key = (package.ecosystem.lower(), manifest_path,
                       entry["package"].casefold(), bool(entry["minimum_fixed_version"]))
                group = grouped.setdefault(key, {"entries": [], "affected_packages": set(), "is_update": False,
                                                 "requires": False, "unverified": False, "real_failure": False, "notes": [], "verified": set()})
                if entry not in group["entries"]:
                    group["entries"].append(entry)
                group["affected_packages"].add(package.package)
                group["is_update"] = group["is_update"] or package.is_update
                recommendation = next((r for r in package.package_upgrade_recommendations
                                       if r.package.casefold() == entry["package"].casefold()), None)
                if recommendation is None:
                    # The resolver records why no parent upgrade was found as "<parent> <version> (<action>): <reason>".
                    prefix = f"{entry['package'].casefold()} "
                    for note in package.notes.splitlines():
                        if note.casefold().startswith(prefix) and note not in group["notes"]:
                            group["notes"].append(note)
                if recommendation is not None and recommendation.requires_verification:
                    group["requires"] = True
                    if package.verified_version(recommendation.package):
                        group["verified"].add(package.verified_version(recommendation.package))
                    else:
                        group["unverified"] = True
                        by_message: dict[str, list[str]] = {}
                        for c in recommendation.qualifying_upgrade_versions:
                            if c.verification_status == "FAILED" and c.verification_message:
                                by_message.setdefault(c.verification_message, []).append(c.version)
                        if not by_message or not all(message.startswith(ENVIRONMENT_MESSAGES) for message in by_message):
                            group["real_failure"] = True
                        failures = [f"{versions[0]}: {message}" if len(versions) == 1
                                    else f"{versions[0]} to {versions[-1]} ({len(versions)} versions): {message}"
                                    for message, versions in by_message.items()]
                        for note in failures or ([package.notes] if package.notes else []):
                            if note not in group["notes"]:
                                group["notes"].append(note)

        targets = []
        for key, group in grouped.items():
            entries = group["entries"]
            target = {key: value for key, value in entries[0].items() if key not in {"qualifying_versions", "review_status", "allow_prerelease"}}
            target["is_update"] = group["is_update"]
            target["verification_status"] = (
                None if not group["requires"] else "SUCCESS" if not group["unverified"]
                else "FAILED" if group["real_failure"] else "NOT VERIFIED")
            target["verification_notes"] = "\n".join(group["notes"])
            target["verified_version"] = (
                ", ".join(sorted(group["verified"])) if target["verification_status"] == "SUCCESS" else "")
            target["affected_packages"] = sorted(group["affected_packages"])
            current_versions = sorted({entry["current_version"] for entry in entries if entry["current_version"]})
            target["current_version"] = ", ".join(current_versions)
            evidenced = [set(entry["qualifying_versions"]) for entry in entries
                         if entry["qualifying_versions"] is not None]
            common = set.intersection(*evidenced) if evidenced else {
                entry["minimum_fixed_version"] for entry in entries if entry["minimum_fixed_version"]}
            parsed = {}
            for candidate in common:
                try:
                    version = Version(candidate)
                    if all(entry["minimum_fixed_version"] and version >= Version(entry["minimum_fixed_version"])
                           for entry in entries):
                        parsed[version] = candidate
                except InvalidVersion:
                    continue
            ordered = sorted(parsed)
            minimum_versions = {}
            for entry in entries:
                try:
                    minimum_versions[Version(entry["minimum_fixed_version"])] = entry["minimum_fixed_version"]
                except InvalidVersion:
                    continue
            target["minimum_fixed_version"] = minimum_versions[max(minimum_versions)] if minimum_versions else ""
            target["highest_fixed_version"] = parsed[ordered[-1]] if ordered and evidenced else ""
            try:
                current_majors = {Version(current).major for current in current_versions}
            except InvalidVersion:
                current_majors = set()
            # Only successful reviews establish ceilings. The initial compatible
            # value is an inferred candidate, not an upper bound.
            try:
                compatibility_limits = [
                    Version(entry["compatible_version"]) for entry in entries
                    if entry["review_status"] == "upgrade_found"
                ]
                limits_valid = True
            except (InvalidVersion, TypeError):
                compatibility_limits, limits_valid = [], False
            allowed = [
                version for version in ordered
                if evidenced and current_majors == {version.major}
                and (not (version.is_prerelease or version.is_devrelease)
                     or all(entry["allow_prerelease"] for entry in entries))
                and limits_valid and all(version <= limit for limit in compatibility_limits)
                and all(version > Version(current) for current in current_versions)
            ]
            # Retain a single entry's preferred candidate only if evidence supports it.
            # Identical entries follow the same checks after deduplication.
            try:
                preferred = Version(entries[0]["compatible_version"]) if len(entries) == 1 else None
            except (InvalidVersion, TypeError):
                preferred = None
            chosen = preferred if preferred in allowed else next(iter(allowed), None)
            target["compatible_version"] = parsed[chosen] if chosen is not None else ""
            if any(v.is_prerelease or v.is_devrelease for v in ordered):
                target["prerelease_fallback"] = True
            if target["verification_status"] is None and chosen is None:
                target["verification_status"] = "NOT VERIFIED"
                target["verification_notes"] = target["verification_notes"] or "No upgrade candidate was identified for this package, so there was nothing to verify."
            targets.append((key, target))
        # An unresolved entry for a package that has a fixed target is folded into it.
        fixed = {key[:3]: target for key, target in targets if key[3]}
        merged = []
        for key, target in targets:
            owner = fixed.get(key[:3])
            if key[3] or owner is None:
                merged.append(target)
            else:
                owner["affected_packages"] = sorted({*owner["affected_packages"], *target["affected_packages"]})
        return merged
