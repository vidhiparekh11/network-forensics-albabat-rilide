from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Packet:
    """Normalized packet record; detectors only ever see this."""
    ts: float
    src: str
    dst: str
    proto: str                     # "TCP" | "UDP" | "OTHER"
    sport: int = 0
    dport: int = 0
    length: int = 0
    flags: str = ""                # TCP flags, e.g. "S", "SA", "PA"
    dns_query: Optional[str] = None
    dns_rcode: Optional[int] = None
    dns_qtype: Optional[int] = None
    http: Optional[dict] = None    # method, host, uri, ua


@dataclass
class Finding:
    severity: str                  # low | medium | high
    category: str
    title: str
    detail: str
    iocs: dict = field(default_factory=dict)   # {"ip": [...], "domain": [...], ...}
    evidence: dict = field(default_factory=dict)

    @property
    def attack(self):
        from .attack import techniques
        return [{"id": i, "name": n} for i, n in techniques(self.category)]

    def to_dict(self):
        d = self.__dict__.copy()
        d["attack"] = self.attack
        return d
