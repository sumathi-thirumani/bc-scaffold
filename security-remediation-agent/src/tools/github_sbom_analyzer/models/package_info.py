from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class PackageInfo:
    name: str
    version: str
    spdx_id: str
    purl: Optional[str]
    ecosystem: str
    dependency_type: str
    source_packages: list[str]
    