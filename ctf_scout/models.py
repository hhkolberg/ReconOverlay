from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass(frozen=True)
class ExploitRef:
    source: str
    title: str
    url: str
    stars: int = 0
    description: str = ""
    exact: bool = False


@dataclass
class CVEEntry:
    cve_id: str
    description: str
    cvss_score: float
    severity: str
    keyword: str
    published: str = ""
    epss: Optional[float] = None
    epss_percentile: Optional[float] = None
    exact_refs: List[ExploitRef] = field(default_factory=list)
    related_refs: List[ExploitRef] = field(default_factory=list)

    @property
    def has_exact_exploits(self) -> bool:
        return bool(self.exact_refs)

    @property
    def risk_sort(self) -> tuple:
        return (
            1 if self.has_exact_exploits else 0,
            self.epss if self.epss is not None else -1.0,
            self.cvss_score,
            self.published,
        )


@dataclass
class ActivityItem:
    keyword: str
    state: str
    detail: str = ""
    timestamp: float = 0.0
