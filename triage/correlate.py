"""Group alerts into cases: one actor, or one campaign spanning several actors.

Alerts are linked when they come from the same source IP, or when their sources
used the same infrastructure: payload/C2 server, payload hash, mining wallet or
pool, or planted SSH key (see ``triage.iocs.LINKING_TYPES``). A Mirai botnet
hitting the sensor from 30 infected routers becomes one case that names the
shared C2, instead of 60 alerts in the queue.

Shared SSH client fingerprints (HASSH) are reported but do not link: common
libraries like Go's x/crypto/ssh produce the same HASSH for unrelated actors.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from triage.iocs import indicators_from_context

Pair = tuple[dict[str, Any], dict[str, Any]]  # (alert, enrichment context)


@dataclass
class Case:
    case_id: str
    alerts: list[dict[str, Any]]
    contexts: dict[str, dict[str, Any]]  # src_ip -> enrichment context
    shared_indicators: list[dict[str, Any]] = field(default_factory=list)

    @property
    def src_ips(self) -> list[str]:
        return sorted({a["src_ip"] for a in self.alerts})

    def summary(self) -> dict[str, Any]:
        """The case as the model sees it: alerts plus what links them."""
        rules = sorted({a["rule_id"] for a in self.alerts})
        return {
            "case_id": self.case_id,
            "source_ips": self.src_ips,
            "alert_count": len(self.alerts),
            "rules_fired": rules,
            "first_seen": min(a["first_seen"] for a in self.alerts),
            "last_seen": max(a["last_seen"] for a in self.alerts),
            "linked_by": self.shared_indicators or "single source IP",
            "alerts": self.alerts,
        }


class _UnionFind:
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def find(self, x: str) -> str:
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[max(ra, rb)] = min(ra, rb)


def case_id_for(src_ips: list[str]) -> str:
    return "case-" + hashlib.sha1("|".join(sorted(src_ips)).encode()).hexdigest()[:10]


def build_cases(pairs: list[Pair], link_infrastructure: bool = True) -> list[Case]:
    uf = _UnionFind()
    by_ip_indicators: dict[str, set[tuple[str, str]]] = defaultdict(set)
    for alert, context in pairs:
        uf.find(alert["src_ip"])
        if link_infrastructure:
            by_ip_indicators[alert["src_ip"]] |= indicators_from_context(alert, context)

    owners: dict[tuple[str, str], set[str]] = defaultdict(set)
    for ip, indicators in by_ip_indicators.items():
        for indicator in indicators:
            owners[indicator].add(ip)
    for indicator, ips in owners.items():
        ips_list = sorted(ips)
        for other in ips_list[1:]:
            uf.union(ips_list[0], other)

    grouped: dict[str, list[Pair]] = defaultdict(list)
    for alert, context in pairs:
        grouped[uf.find(alert["src_ip"])].append((alert, context))

    cases = []
    for members in grouped.values():
        alerts = sorted((a for a, _ in members), key=lambda a: (a["first_seen"], a["rule_id"]))
        contexts: dict[str, dict[str, Any]] = {}
        for alert, context in sorted(members, key=lambda p: p[0]["first_seen"]):
            contexts.setdefault(alert["src_ip"], context)  # earliest alert's window per source
        ips = sorted(contexts)
        shared = [
            {"type": t, "value": v, "seen_from": sorted(owners[(t, v)])}
            for (t, v) in sorted(owners)
            if len(owners[(t, v)]) > 1 and owners[(t, v)] <= set(ips)
        ]
        cases.append(Case(case_id_for(ips), alerts, contexts, shared))
    return sorted(cases, key=lambda c: c.alerts[0]["first_seen"])
