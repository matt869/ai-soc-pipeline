"""Normalize Cowrie JSON log events into rows for the Sentinel ``Cowrie_CL`` table.

Cowrie writes one JSON object per line to ``var/log/cowrie/cowrie.json``. Field
names vary slightly between event types and Cowrie versions, so everything that
leaves the honeypot goes through :func:`parse_event`. The output keys are exactly
the table columns in ``siem/infra/table-schema.json``.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Column name -> Log Analytics type. Must match siem/infra/table-schema.json and the
# stream declaration in siem/infra/dcr-cowrie.json (tests/test_schema_consistency.py checks this).
COLUMNS: dict[str, str] = {
    "TimeGenerated": "datetime",
    "eventid": "string",
    "session": "string",
    "src_ip": "string",
    "src_port": "int",
    "dst_ip": "string",
    "dst_port": "int",
    "sensor": "string",
    "protocol": "string",
    "username": "string",
    "password": "string",
    "input": "string",
    "url": "string",
    "outfile": "string",
    "shasum": "string",
    "duration": "real",
    "client_version": "string",
    "hassh": "string",
    "message": "string",
}

# Cowrie field name -> column name, where they differ.
_RENAMES = {"version": "client_version"}

_MAX_FIELD_LEN = 8192  # keep a single attacker-controlled field from bloating a row


def _parse_timestamp(value: Any) -> str | None:
    if not value:
        return None
    if isinstance(value, (int, float)):
        dt = datetime.fromtimestamp(value, tz=UTC)
    else:
        text = str(value).strip().replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _coerce(value: Any, col_type: str) -> Any:
    if value is None or value == "":
        return None
    try:
        if col_type == "int":
            return int(value)
        if col_type == "real":
            return float(value)
    except (TypeError, ValueError):
        return None
    if col_type == "string":
        if isinstance(value, (list, dict)):
            value = json.dumps(value, separators=(",", ":"))
        text = str(value)
        return text[:_MAX_FIELD_LEN]
    return value


def parse_event(raw: dict[str, Any]) -> dict[str, Any] | None:
    """Convert one raw Cowrie event to a table row. Returns None for unusable events."""
    if not isinstance(raw, dict) or not raw.get("eventid"):
        return None
    timestamp = _parse_timestamp(raw.get("timestamp"))
    if timestamp is None:
        return None

    row: dict[str, Any] = {name: None for name in COLUMNS}
    row["TimeGenerated"] = timestamp
    for key, value in raw.items():
        column = _RENAMES.get(key, key)
        if column in COLUMNS and column != "TimeGenerated":
            row[column] = _coerce(value, COLUMNS[column])

    # file_download events carry the saved path as "outfile" in newer Cowrie and "destfile" in older.
    if row["outfile"] is None and raw.get("destfile"):
        row["outfile"] = _coerce(raw["destfile"], "string")
    # Older Cowrie versions report the SSH client version as a list of bytes-ish strings.
    if row["client_version"] and row["client_version"].startswith("[\""):
        row["client_version"] = row["client_version"].strip('[]"')
    return row


def parse_line(line: str) -> dict[str, Any] | None:
    line = line.strip()
    if not line:
        return None
    try:
        return parse_event(json.loads(line))
    except json.JSONDecodeError:
        return None


def parse_lines(lines: Iterable[str]) -> Iterator[dict[str, Any]]:
    for line in lines:
        row = parse_line(line)
        if row is not None:
            yield row


def load_events(path: str | Path) -> list[dict[str, Any]]:
    """Load events from a Cowrie JSON-lines file or a JSON array file.

    Rows that are already normalized (have ``TimeGenerated``) pass through unchanged,
    so this also reads the shipper's dry-run output and siem/samples/cowrie-sample.json.
    """
    text = Path(path).read_text(encoding="utf-8")
    stripped = text.lstrip()
    if stripped.startswith("["):
        records = json.loads(stripped)
    else:
        records = []
        for line in text.splitlines():
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue  # blank or corrupt line (e.g. truncated by a crash mid-write)

    rows = []
    for record in records:
        if isinstance(record, dict) and "TimeGenerated" in record:
            rows.append({name: record.get(name) for name in COLUMNS})
        else:
            row = parse_event(record)
            if row is not None:
                rows.append(row)
    rows.sort(key=lambda r: r["TimeGenerated"])
    return rows


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Normalize a Cowrie JSON log to Cowrie_CL rows (JSON lines).")
    parser.add_argument("path", help="cowrie.json (JSON lines) or a JSON array file")
    args = parser.parse_args()
    for event in load_events(args.path):
        sys.stdout.write(json.dumps(event) + "\n")
