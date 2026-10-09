"""SQLite record of every alert and verdict.

Continuous triage (``--watch``) re-runs the detections every cycle over an
overlapping window, so the same alert comes back many times. The store makes
sure each alert is paid for once, remembers which verdicts were already written
back to Sentinel, and is what the HTML report and the IOC export read from.
Failed triage attempts are stored but do not count as done, so they retry.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    alert_id    TEXT PRIMARY KEY,
    rule_id     TEXT NOT NULL,
    src_ip      TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    alert_json  TEXT NOT NULL,
    enrichment_json TEXT,
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS verdicts (
    alert_id    TEXT PRIMARY KEY REFERENCES alerts(alert_id),
    case_id     TEXT,
    verdict     TEXT,
    severity    TEXT,
    escalate    INTEGER,
    confidence  REAL,
    result_json TEXT NOT NULL,
    error       TEXT,
    triaged_at  TEXT NOT NULL,
    writeback   TEXT
);
CREATE TABLE IF NOT EXISTS spend (
    day         TEXT PRIMARY KEY,            -- UTC date
    usd         REAL NOT NULL DEFAULT 0,
    calls       INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS feedback (
    alert_id    TEXT PRIMARY KEY REFERENCES alerts(alert_id),
    verdict     TEXT NOT NULL,               -- malicious | suspicious | benign
    severity    TEXT,
    escalate    INTEGER,
    analyst     TEXT,
    source      TEXT NOT NULL,               -- cli | sentinel
    note        TEXT,
    recorded_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS verdicts_case ON verdicts(case_id);
CREATE INDEX IF NOT EXISTS alerts_ip ON alerts(src_ip);
"""


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


class Store:
    def __init__(self, path: str | Path = "data/soc.db"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.db = sqlite3.connect(self.path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        self._migrate()

    def _migrate(self) -> None:
        columns = {r["name"] for r in self.db.execute("PRAGMA table_info(verdicts)")}
        if "incident_id" not in columns:
            with self.db:
                self.db.execute("ALTER TABLE verdicts ADD COLUMN incident_id TEXT")

    def close(self) -> None:
        self.db.close()

    def triaged_ids(self, alert_ids: Iterable[str]) -> set[str]:
        ids = list(alert_ids)
        if not ids:
            return set()
        done: set[str] = set()
        for start in range(0, len(ids), 500):
            chunk = ids[start:start + 500]
            rows = self.db.execute(
                # Only "?" placeholders are interpolated; the ids themselves are bound parameters.
                f"SELECT alert_id FROM verdicts WHERE verdict IS NOT NULL AND alert_id IN ({','.join('?' * len(chunk))})",  # noqa: S608
                chunk)
            done.update(r["alert_id"] for r in rows)
        return done

    def save(self, alert: dict[str, Any], enrichment: dict[str, Any] | None, result: dict[str, Any]) -> None:
        triage = result.get("triage") or {}
        with self._lock, self.db:
            self.db.execute(
                "INSERT INTO alerts (alert_id, rule_id, src_ip, first_seen, last_seen, alert_json, enrichment_json, "
                "created_at) VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(alert_id) DO UPDATE SET "
                "last_seen=excluded.last_seen, alert_json=excluded.alert_json, enrichment_json=excluded.enrichment_json",
                (alert["alert_id"], alert["rule_id"], alert["src_ip"], alert["first_seen"], alert["last_seen"],
                 json.dumps(alert), json.dumps(enrichment) if enrichment is not None else None, _now()))
            self.db.execute(
                "INSERT INTO verdicts (alert_id, case_id, verdict, severity, escalate, confidence, result_json, error, "
                "triaged_at) VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(alert_id) DO UPDATE SET "
                "case_id=excluded.case_id, verdict=excluded.verdict, severity=excluded.severity, "
                "escalate=excluded.escalate, confidence=excluded.confidence, result_json=excluded.result_json, "
                "error=excluded.error, triaged_at=excluded.triaged_at",
                (alert["alert_id"], result.get("case_id"), triage.get("verdict"), triage.get("severity"),
                 None if not triage else int(triage["escalate"]), triage.get("confidence"), json.dumps(result),
                 result.get("error"), _now()))

    def mark_written_back(self, alert_id: str, status: str, incident_id: str | None = None) -> None:
        with self._lock, self.db:
            self.db.execute("UPDATE verdicts SET writeback=?, incident_id=COALESCE(?, incident_id) WHERE alert_id=?",
                            (status, incident_id, alert_id))

    # --- spend --------------------------------------------------------------------------
    def add_spend(self, day: str, usd: float) -> None:
        with self._lock, self.db:
            self.db.execute("INSERT INTO spend VALUES (?,?,1) ON CONFLICT(day) DO UPDATE SET "
                            "usd = usd + excluded.usd, calls = calls + 1", (day, usd))

    def spend(self, day: str) -> float:
        row = self.db.execute("SELECT usd FROM spend WHERE day=?", (day,)).fetchone()
        return row["usd"] if row else 0.0

    # --- analyst feedback ------------------------------------------------------------------
    def alert_ids_for(self, ref: str) -> list[str]:
        """An alert id, or every alert in a case id."""
        rows = self.db.execute("SELECT alert_id FROM verdicts WHERE alert_id=? OR case_id=? ORDER BY alert_id", (ref, ref))
        return [r["alert_id"] for r in rows]

    def alerts_for_incident(self, incident_id: str) -> list[str]:
        rows = self.db.execute("SELECT alert_id FROM verdicts WHERE incident_id=?", (incident_id,))
        return [r["alert_id"] for r in rows]

    def save_feedback(self, alert_id: str, verdict: str, severity: str | None, escalate: bool | None,
                      analyst: str | None, source: str, note: str | None = None) -> None:
        with self._lock, self.db:
            self.db.execute(
                "INSERT INTO feedback VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(alert_id) DO UPDATE SET "
                "verdict=excluded.verdict, severity=excluded.severity, escalate=excluded.escalate, "
                "analyst=excluded.analyst, source=excluded.source, note=excluded.note, recorded_at=excluded.recorded_at",
                (alert_id, verdict, severity, None if escalate is None else int(escalate), analyst, source, note, _now()))

    def feedback_rows(self) -> list[dict[str, Any]]:
        """Analyst labels joined with the alert, the enrichment the model saw, and the model's verdict."""
        rows = self.db.execute(
            "SELECT f.*, a.alert_json, a.enrichment_json, a.rule_id, a.src_ip, v.verdict AS ai_verdict, "
            "v.severity AS ai_severity, v.escalate AS ai_escalate FROM feedback f JOIN alerts a USING(alert_id) "
            "LEFT JOIN verdicts v USING(alert_id) ORDER BY a.first_seen")
        return [dict(r) for r in rows]

    def pending_writeback(self) -> list[dict[str, Any]]:
        rows = self.db.execute(
            "SELECT a.alert_json, v.result_json FROM verdicts v JOIN alerts a USING(alert_id) "
            "WHERE v.verdict IS NOT NULL AND v.writeback IS NULL ORDER BY a.first_seen")
        return [{"alert": json.loads(r["alert_json"]), "result": json.loads(r["result_json"])} for r in rows]

    def records(self) -> Iterator[dict[str, Any]]:
        """Every stored alert in the same shape as the triage JSONL output."""
        rows = self.db.execute(
            "SELECT a.alert_json, a.enrichment_json, v.result_json, v.writeback FROM alerts a "
            "LEFT JOIN verdicts v USING(alert_id) ORDER BY a.first_seen")
        for r in rows:
            yield {"alert": json.loads(r["alert_json"]),
                   "enrichment": json.loads(r["enrichment_json"]) if r["enrichment_json"] else None,
                   "result": json.loads(r["result_json"]) if r["result_json"] else None,
                   "writeback": r["writeback"]}

    def stats(self) -> dict[str, Any]:
        row = self.db.execute(
            "SELECT COUNT(*) AS alerts, SUM(verdict IS NOT NULL) AS triaged, SUM(error IS NOT NULL AND verdict IS NULL) "
            "AS errors, SUM(escalate = 1) AS escalated, COUNT(DISTINCT case_id) AS cases FROM alerts "
            "LEFT JOIN verdicts USING(alert_id)").fetchone()
        return dict(row)
