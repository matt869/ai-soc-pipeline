import json

import pytest

import ingestion.ship_logs as ship_logs
from ingestion.ship_logs import Checkpoint, Shipper, make_file_sender, read_new_lines

LINE = json.dumps({"eventid": "cowrie.session.connect", "timestamp": "2026-09-01T10:00:00Z",
                   "src_ip": "203.0.113.1", "session": "a"})


def test_partial_line_is_left_for_next_read(tmp_path):
    log = tmp_path / "cowrie.json"
    log.write_bytes((LINE + "\n" + LINE[:20]).encode())
    lines, offset = read_new_lines(log, Checkpoint())
    assert lines == [LINE]
    assert offset == len(LINE) + 1


def test_truncation_restarts_from_zero(tmp_path):
    log = tmp_path / "cowrie.json"
    log.write_bytes((LINE + "\n").encode())
    lines, _ = read_new_lines(log, Checkpoint(offset=10_000))
    assert lines == [LINE]


def test_run_once_ships_and_checkpoints(tmp_path):
    log, out, state = tmp_path / "cowrie.json", tmp_path / "out.jsonl", tmp_path / "state.json"
    log.write_bytes(((LINE + "\n") * 5 + "garbage\n").encode())
    assert Shipper(log, state, make_file_sender(out), batch_size=2).run_once() == 5
    assert len(out.read_text().splitlines()) == 5
    # Restarting with the saved checkpoint sends nothing new...
    assert Shipper(log, state, make_file_sender(out), batch_size=2).run_once() == 0
    # ...until more lines arrive.
    with log.open("ab") as fh:
        fh.write((LINE + "\n").encode())
    assert Shipper(log, state, make_file_sender(out), batch_size=2).run_once() == 1


def test_failed_upload_does_not_advance_checkpoint(tmp_path, monkeypatch):
    monkeypatch.setattr(ship_logs.time, "sleep", lambda s: None)
    log, state = tmp_path / "cowrie.json", tmp_path / "state.json"
    log.write_bytes((LINE + "\n").encode())

    def broken(rows):
        raise ConnectionError("boom")

    with pytest.raises(ConnectionError):
        Shipper(log, state, broken, batch_size=10).run_once()
    assert Checkpoint.load(state).offset == 0
