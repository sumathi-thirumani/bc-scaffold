from collections import defaultdict
from typing import Optional

from .graph import SBOMGraph


class SBOMService:
    def __init__(self, graph: SBOMGraph):
        self.graph = graph

    def analyze(
        self,
        package: Optional[str] = None,
        ecosystem: Optional[str] = None,
    ):
        items = (
            self.graph.get_by_name(package)
            if package
            else self.graph.get_by_ecosystem(ecosystem)
        )

        counts = defaultdict(int)
        for i in items:
            counts[i.dependency_type] += 1

        return {
            "total": len(items),
            "direct": counts["direct"],
            "transitive": counts["transitive"],
            "unknown": counts["unknown"],
            "packages": [i.__dict__ for i in items],
        }

    def list_ecosystems(self):
        eco_counts = defaultdict(int)

        for i in self.graph.get_all():
            eco_counts[i.ecosystem] += 1

        return [
            {"ecosystem": k, "count": v}
            for k, v in sorted(eco_counts.items())
        ]
