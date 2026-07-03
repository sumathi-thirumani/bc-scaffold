from langchain_core.tools import tool
from pydantic import BaseModel, Field

from .core.fetcher import fetch_github_sbom
from .core.graph import SBOMGraph
from .core.sbom_service import SBOMService


class SBOMInput(BaseModel):
    owner: str = Field(...)
    repo: str = Field(...)
    package: str | None = None
    ecosystem: str | None = None
    list_ecosystems: bool = False


@tool("analyze_github_sbom", args_schema=SBOMInput)
async def analyze_sbom(owner: str, repo: str, package=None, ecosystem=None, list_ecosystems=False):
    """Analyze a repository SBOM and summarize package dependency relationships."""
    doc = await fetch_github_sbom(owner, repo)
    graph = SBOMGraph(doc)
    service = SBOMService(graph)

    if list_ecosystems:
        return {
            "mode": "ecosystems",
            "data": service.list_ecosystems(),
        }

    return {
        "mode": "packages",
        "data": service.analyze(package, ecosystem),
    }


sbom_analysis_tool = analyze_sbom
