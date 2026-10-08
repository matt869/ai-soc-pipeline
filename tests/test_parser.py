import json

from ingestion.parsers.cowrie_parser import COLUMNS, load_events, parse_event, parse_line


def test_command_event_normalized():
    row = parse_event({
        "eventid": "cowrie.command.input", "timestamp": "2026-09-01T10:00:00.123456Z",
        "src_ip": "203.0.113.5", "src_port": "50123", "session": "abc", "input": "uname -a", "sensor": "s1",
    })
    assert set(row) == set(COLUMNS)
    assert row["TimeGenerated"] == "2026-09-01T10:00:00.123456Z"
    assert row["src_port"] == 50123
    assert row["input"] == "uname -a"
    assert row["username"] is None


def test_renames_and_fallbacks():
    version = parse_event({"eventid": "cowrie.client.version", "timestamp": "2026-09-01T10:00:00Z",
                           "version": "SSH-2.0-Go", "session": "a", "src_ip": "1.2.3.4"})
    assert version["client_version"] == "SSH-2.0-Go"
    download = parse_event({"eventid": "cowrie.session.file_download", "timestamp": "2026-09-01T10:00:00+00:00",
                            "destfile": "var/lib/cowrie/downloads/abc", "src_ip": "1.2.3.4", "session": "a"})
    assert download["outfile"] == "var/lib/cowrie/downloads/abc"
    closed = parse_event({"eventid": "cowrie.session.closed", "timestamp": "2026-09-01T10:00:00Z",
                          "duration": "12.5", "src_ip": "1.2.3.4", "session": "a"})
    assert closed["duration"] == 12.5


def test_rejects_garbage():
    assert parse_line("not json") is None
    assert parse_line("") is None
    assert parse_event({"timestamp": "2026-09-01T10:00:00Z"}) is None  # no eventid
    assert parse_event({"eventid": "x", "timestamp": "yesterday"}) is None


def test_long_attacker_input_truncated():
    row = parse_event({"eventid": "cowrie.command.input", "timestamp": "2026-09-01T10:00:00Z",
                       "input": "A" * 50_000, "src_ip": "1.2.3.4", "session": "a"})
    assert len(row["input"]) == 8192


def test_load_events_accepts_raw_and_normalized(tmp_path, sim):
    raw = tmp_path / "cowrie.json"
    raw.write_text("".join(json.dumps(e) + "\n" for e in sim.events[:50]) + "garbage line\n")
    rows = load_events(raw)
    assert len(rows) == 50
    normalized = tmp_path / "rows.json"
    normalized.write_text(json.dumps(rows))
    assert load_events(normalized) == rows
