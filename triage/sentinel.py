"""Read detections and activity context from a Sentinel (Log Analytics) workspace.

Runs each detection in detections/kql over a lookback window and turns the
result rows into the same alert shape the local rules produce, so the triage
agent does not care where an alert came from. Authentication uses
DefaultAzureCredential (az login, managed identity, or service-principal env vars).
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from detections.local_rules import build_alert
from detections.rules import load_rules
from ingestion.parsers.cowrie_parser import COLUMNS

log = logging.getLogger(__name__)


def _client():
    from azure.identity import DefaultAzureCredential
    from azure.monitor.query import LogsQueryClient

    return LogsQueryClient(DefaultAzureCredential())


def _rows(result) -> list[dict[str, Any]]:
    from azure.monitor.query import LogsQueryStatus

    if result.status == LogsQueryStatus.PARTIAL:
        log.warning("Partial query result: %s", result.partial_error)
        tables = result.partial_data
    else:
        tables = result.tables
    rows = []
    for table in tables:
        columns = list(table.columns)
        for row in table.rows:
            rows.append(dict(zip(columns, row)))
    return rows


def _iso(value: Any) -> str | None:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
    return value


def _jsonable(value: Any) -> Any:
    if isinstance(value, datetime):
        return _iso(value)
    if isinstance(value, list):
        return [_jsonable(v) for v in value]
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    return value


class SentinelEventSource:
    def __init__(self, workspace_id: str, client=None):
        self.workspace_id = workspace_id
        self.client = client or _client()

    def query(self, kql: str, timespan) -> list[dict[str, Any]]:
        return _rows(self.client.query_workspace(self.workspace_id, kql, timespan=timespan))

    def events_for_ip(self, ip: str, start: datetime, end: datetime) -> list[dict[str, Any]]:
        safe_ip = ip.replace('"', "")
        kql = f'Cowrie_CL | where src_ip == "{safe_ip}" | project {", ".join(COLUMNS)} | order by TimeGenerated asc | take 2000'
        return [{k: _jsonable(v) for k, v in row.items()} for row in self.query(kql, (start, end))]

    def run_detections(self, lookback: timedelta, rule_ids: list[str] | None = None) -> list[dict[str, Any]]:
        alerts = []
        for rule_id, rule in load_rules().items():
            if rule_ids and rule_id not in rule_ids:
                continue
            try:
                rows = self.query(rule.query, lookback)
            except Exception as exc:  # HttpResponseError for a bad query should not stop the other rules
                log.error("Detection %s failed: %s", rule_id, exc)
                continue
            for row in rows:
                row = {k: _jsonable(v) for k, v in row.items()}
                first = row.get("FirstSeen") or row.get("TimeGenerated") or row.get("Window")
                last = row.get("LastSeen") or first
                evidence = {k: v for k, v in row.items()
                            if k not in ("src_ip", "session", "FirstSeen", "LastSeen", "TimeGenerated")}
                alerts.append(build_alert(rule_id, row["src_ip"], row.get("session"), first, last, evidence,
                                          key=[row["src_ip"], row.get("session"), row.get("Window") or first]))
            log.info("%s: %d alerts", rule_id, len(rows))
        return sorted(alerts, key=lambda a: (a["first_seen"], a["rule_id"]))
