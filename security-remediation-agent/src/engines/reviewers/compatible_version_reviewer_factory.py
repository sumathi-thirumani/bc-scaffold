"""Select one compatible-version reviewer per ecosystem family in a plan."""
import logging
from typing import Protocol

from ...models.remediation_plan import RemediationPlan
from ...tools.ecosystem_manifest_tool import ManifestTool
from .dotnet_compatible_version_reviewer import DotNetCompatibleVersionReviewer
from .npm_compatible_version_reviewer import NpmCompatibleVersionReviewer, NPM_ECOSYSTEMS
from .pip_compatible_version_reviewer import PythonCompatibleVersionReviewer, PYTHON_ECOSYSTEMS

logger = logging.getLogger(__name__)


class CompatibleVersionReviewer(Protocol):
    """Define the asynchronous contract for enriching candidate compatibility evidence."""
    async def review(self, remediation_plan: RemediationPlan, repo: dict[str, str], *,
                     ref: str | None = None) -> RemediationPlan: ...


class CompatibleVersionReviewerFactory:
    """Select one reviewer for each ecosystem family in the input.

    Core idea: inspect package ecosystems independently of temporary group names,
    avoid duplicate family reviews, and share manifest access and update policy."""
    def __init__(self, manifest_tool: ManifestTool, additional_updates: bool = False) -> None:
        self.manifest_tool = manifest_tool
        self.additional_updates = additional_updates

    @staticmethod
    def _reviewer_type(ecosystem: str):
        normalized = ecosystem.lower()
        if normalized in NPM_ECOSYSTEMS:
            return NpmCompatibleVersionReviewer
        if normalized == "nuget":
            return DotNetCompatibleVersionReviewer
        if normalized in PYTHON_ECOSYSTEMS:
            return PythonCompatibleVersionReviewer
        raise ValueError(f"Unsupported compatible-version review ecosystem: {ecosystem}")

    def create(self, ecosystem: str) -> CompatibleVersionReviewer:
        return self._reviewer_type(ecosystem)(self.manifest_tool, additional_updates=self.additional_updates)

    def for_plan(self, plan: RemediationPlan) -> list[CompatibleVersionReviewer]:
        """Select one reviewer per family using package ecosystems rather than bundle names."""
        selected = {}
        for bundle in plan.remediation_plan_bundles:
            for package in bundle.packages:
                try:
                    reviewer_type = self._reviewer_type(package.ecosystem)
                except ValueError:
                    logger.debug("Skipping compatible-version review for %s", package.ecosystem)
                    continue
                selected.setdefault(reviewer_type, package.ecosystem)
        return [self.create(ecosystem) for ecosystem in selected.values()]
