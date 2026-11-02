"""Select one compatible-version reviewer per ecosystem family in a plan."""
import logging
from typing import Protocol

from ...models.remediation_plan import RemediationPlan
from ...tools.ecosystem_manifest_tool import ManifestTool
from .dotnet_compatible_version_reviewer import DotNetCompatibleVersionReviewer
from .npm_comptabile_version_reviewer import NpmCompatibleVersionReviewer, NPM_ECOSYSTEMS
from .python_compatible_version_reviewer import PythonCompatibleVersionReviewer, PYTHON_ECOSYSTEMS

logger = logging.getLogger(__name__)


class CompatibleVersionReviewer(Protocol):
    async def review(self, remediation_plan: RemediationPlan, repo: dict[str, str], *,
                     ref: str | None = None) -> RemediationPlan: ...


class CompatibleVersionReviewerFactory:
    def __init__(self, manifest_tool: ManifestTool) -> None:
        self.manifest_tool = manifest_tool

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
        return self._reviewer_type(ecosystem)(self.manifest_tool)

    def for_plan(self, plan: RemediationPlan) -> list[CompatibleVersionReviewer]:
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
