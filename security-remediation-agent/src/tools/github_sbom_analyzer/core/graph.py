from collections import defaultdict, deque
from typing import Optional

from spdx_tools.spdx.model import Package, RelationshipType
from spdx_tools.spdx.model.spdx_no_assertion import SpdxNoAssertion
from spdx_tools.spdx.model.spdx_none import SpdxNone
from spdx_tools.spdx.model.document import Document

from ..models.package_info import PackageInfo


class SBOMGraph:
    def __init__(self, doc: Document):
        self.doc = doc

        # fast lookup
        self.by_id: dict[str, Package] = {self._spdx_id(p.spdx_id): p for p in doc.packages}
        self.by_name: dict[str, list[PackageInfo]] = defaultdict(list)

        self.children = defaultdict(set)
        self.parents = defaultdict(set)

        for rel in doc.relationships:
            if rel.relationship_type != RelationshipType.DEPENDS_ON:
                continue

            src = self._eid(rel, "element")
            dst = self._eid(rel, "related")

            self.children[src].add(dst)
            self.parents[dst].add(src)

        self.root_ids = self._detect_roots()

        self.direct = self._compute_direct()
        self.visited = self._bfs()

        self.infos = {
            self._spdx_id(p.spdx_id): self._to_info(p) for p in doc.packages
        }

        # name index (fast lookup)
        for info in self.infos.values():
            self.by_name[info.name.lower()].append(info)

    # ── core graph logic ───────────────────────────────

    def _detect_roots(self):
        all_children = {c for v in self.children.values() for c in v}
        roots = set(self.children.keys()) - all_children
        return roots or {self._spdx_id(p.spdx_id) for p in self.doc.packages}

    def _compute_direct(self):
        direct = set()
        for r in self.root_ids:
            direct |= self.children.get(r, set())
        return direct

    def _bfs(self):
        q = deque(self.direct)
        visited = set(self.root_ids) | set(self.direct)

        while q:
            node = q.popleft()
            for c in self.children.get(node, []):
                if c not in visited:
                    visited.add(c)
                    q.append(c)

        return visited

    # ── classification ────────────────────────────────

    def dependency_type(self, spdx_id: str) -> str:
        # BUG FIX: without this check, the repo-root package itself falls
        # through to "transitive" below, since _bfs() seeds `visited` with
        # root_ids as well as direct — it's never wrong per se, but it's
        # misleading for the one node that isn't really a dependency at all.
        if spdx_id in self.root_ids:
            return "root"
        if spdx_id in self.direct:
            return "direct"
        if spdx_id in self.visited:
            return "transitive"
        return "unknown"

    # ── mapping ────────────────────────────────────────

    def _to_info(self, p: Package) -> PackageInfo:
        purl = self._purl(p)

        return PackageInfo(
            name=p.name or "unknown",
            version=p.version or "unknown",
            spdx_id=self._spdx_id(p.spdx_id),
            purl=purl,
            ecosystem=self._ecosystem(purl),
            dependency_type=self.dependency_type(self._spdx_id(p.spdx_id)),
            source_packages=self._sources(self._spdx_id(p.spdx_id)),
        )

    def _purl(self, pkg):
        for r in pkg.external_references or []:
            if r.reference_type == "purl":
                return r.locator
        return None

    def _ecosystem(self, purl: Optional[str]) -> str:
        if purl and purl.startswith("pkg:"):
            return purl.split(":")[1].split("/")[0].lower()
        return "unknown"

    def _sources(self, spdx_id: str):
        out = []
        for parent in self.parents.get(spdx_id, []):
            p = self.by_id.get(parent)
            if p:
                out.append(f"{p.name}@{p.version or ''}")
        return sorted(out)

    def _eid(self, rel, kind: str) -> str:
        # BUG FIX: the real spdx_tools.spdx.model.Relationship fields are
        # `spdx_element_id` (the relationship's source/"element") and
        # `related_spdx_element_id` (the target/"related") — there is no
        # `element_` prefix on the source field. The previous version built
        # the attribute name as f"{kind}_spdx_element_id", which produced
        # "element_spdx_element_id" for the source side — an attribute that
        # never exists on the object. That silently resolved to None via the
        # nested getattr default, collapsing every relationship's source to
        # an empty spdx_id ("").
        #
        # The practical effect: self.children[""] ended up holding *every*
        # dst across the whole document, so _compute_direct() treated every
        # package with any incoming DEPENDS_ON edge as "direct" — including
        # packages several hops deep that should have been "transitive" —
        # and no real package id ever appeared as a key in self.children,
        # so _bfs() had nothing further to walk. Transitive dependencies
        # were never correctly classified as a result.
        #
        # The "related" side happened to work before this fix purely by
        # coincidence: "related_" + "spdx_element_id" already matches the
        # real attribute name.
        attr = "spdx_element_id" if kind == "element" else "related_spdx_element_id"
        value = getattr(rel, attr, None)
        return self._spdx_id(value)

    def _spdx_id(self, value) -> str:
        if value is None or isinstance(value, (SpdxNoAssertion, SpdxNone)):
            return ""
        if isinstance(value, str):
            return value
        if hasattr(value, "document_ref_id") and hasattr(value, "spdx_id"):
            return self._spdx_id(value.spdx_id)
        if hasattr(value, "spdx_id"):
            return self._spdx_id(value.spdx_id)
        return str(value)

    # ── public API ────────────────────────────────────

    def get_all(self):
        return list(self.infos.values())

    def get_by_ecosystem(self, eco: Optional[str]):
        if not eco:
            return self.get_all()
        eco = eco.lower()
        return [i for i in self.infos.values() if i.ecosystem == eco]

    def get_by_name(self, name: str):
        return self.by_name.get(name.lower(), [])

    def ecosystems(self):
        return sorted({i.ecosystem for i in self.infos.values()})