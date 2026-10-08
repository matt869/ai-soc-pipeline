"""Load detection metadata from the header comments of detections/kql/*.kql.

Each KQL file starts with ``// key: value`` lines (name, severity, tactics,
techniques, frequency, period, description). Those headers are the single source
of truth for rule metadata: siem/infra/deploy.ps1 reads them to create Sentinel
analytics rules, and the Python side (local rules, Sentinel query mode) reads
them through this module.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

KQL_DIR = Path(__file__).resolve().parent / "kql"

_HEADER = re.compile(r"^//\s*([a-z_]+)\s*:\s*(.*?)\s*$")
_LIST_KEYS = {"tactics", "techniques"}


@dataclass(frozen=True)
class Rule:
    rule_id: str  # file stem, e.g. "01_ssh_bruteforce"
    name: str
    severity: str
    tactics: tuple[str, ...]
    techniques: tuple[str, ...]
    frequency: str
    period: str
    description: str
    query: str = field(repr=False)


def parse_kql(path: Path) -> Rule:
    meta: dict[str, object] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = _HEADER.match(line)
        if not match:
            if line.strip() and not line.lstrip().startswith("//"):
                break  # headers end at the first line of query text
            continue
        key, value = match.groups()
        meta[key] = tuple(v.strip() for v in value.split(",") if v.strip()) if key in _LIST_KEYS else value
    missing = {"name", "severity", "techniques"} - meta.keys()
    if missing:
        raise ValueError(f"{path.name}: missing header(s) {sorted(missing)}")
    return Rule(
        rule_id=path.stem,
        name=str(meta["name"]),
        severity=str(meta["severity"]),
        tactics=tuple(meta.get("tactics", ())),  # type: ignore[arg-type]
        techniques=tuple(meta["techniques"]),  # type: ignore[arg-type]
        frequency=str(meta.get("frequency", "PT10M")),
        period=str(meta.get("period", "PT1H")),
        description=str(meta.get("description", "")),
        query=path.read_text(encoding="utf-8"),
    )


@lru_cache(maxsize=1)
def load_rules(kql_dir: Path = KQL_DIR) -> dict[str, Rule]:
    return {path.stem: parse_kql(path) for path in sorted(kql_dir.glob("*.kql"))}
