"""Tail Cowrie's JSON log and ship normalized events to Microsoft Sentinel.

Events go through the Azure Monitor Logs Ingestion API (DCE + DCR) into the
``Cowrie_CL`` custom table. The shipper checkpoints its byte offset after each
successful upload, so a restart resumes where it left off (at-least-once
delivery: a crash between upload and checkpoint can re-send one batch).

Examples:
    # Follow the live log on the honeypot (uses managed identity / az login):
    python -m ingestion.ship_logs --log-file /cowrie/var/log/cowrie/cowrie.json

    # One pass over a file, writing to disk instead of Azure:
    python -m ingestion.ship_logs --log-file data/raw/cowrie.json --once --dry-run
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from ingestion.parsers.cowrie_parser import parse_line

log = logging.getLogger("ship_logs")

DEFAULT_STREAM = "Custom-Cowrie_CL"


@dataclass
class Checkpoint:
    inode: int | None = None
    offset: int = 0

    @classmethod
    def load(cls, path: Path) -> Checkpoint:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return cls(inode=data.get("inode"), offset=int(data.get("offset", 0)))
        except (FileNotFoundError, ValueError):
            return cls()

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps({"inode": self.inode, "offset": self.offset}), encoding="utf-8")
        for attempt in range(5):
            try:
                os.replace(tmp, path)
                return
            except PermissionError:
                # Windows: antivirus/indexers briefly lock freshly written files.
                if attempt == 4:
                    raise
                time.sleep(0.05 * (attempt + 1))


def read_new_lines(log_file: Path, checkpoint: Checkpoint, max_bytes: int = 8 * 1024 * 1024) -> tuple[list[str], int]:
    """Return complete lines written since the checkpoint and the offset just past them.

    Detects rotation (new inode) and truncation (file smaller than the offset) and
    restarts from the beginning of the new file. A trailing partial line is left
    for the next read.
    """
    try:
        stat = log_file.stat()
    except FileNotFoundError:
        return [], checkpoint.offset

    if checkpoint.inode is not None and stat.st_ino and stat.st_ino != checkpoint.inode:
        log.info("Log rotated (inode %s -> %s); reading new file from start", checkpoint.inode, stat.st_ino)
        checkpoint.offset = 0
    if stat.st_size < checkpoint.offset:
        log.info("Log truncated (size %d < offset %d); reading from start", stat.st_size, checkpoint.offset)
        checkpoint.offset = 0
    checkpoint.inode = stat.st_ino or None

    with log_file.open("rb") as fh:
        fh.seek(checkpoint.offset)
        chunk = fh.read(max_bytes)

    end = chunk.rfind(b"\n")
    if end == -1:
        return [], checkpoint.offset
    complete = chunk[: end + 1]
    lines = complete.decode("utf-8", errors="replace").splitlines()
    return lines, checkpoint.offset + len(complete)


def make_azure_sender(endpoint: str, rule_id: str, stream: str) -> Callable[[list[dict[str, Any]]], None]:
    from azure.identity import DefaultAzureCredential
    from azure.monitor.ingestion import LogsIngestionClient

    client = LogsIngestionClient(endpoint=endpoint, credential=DefaultAzureCredential(), logging_enable=False)

    def send(rows: list[dict[str, Any]]) -> None:
        # Raises on failure so the checkpoint is not advanced.
        client.upload(rule_id=rule_id, stream_name=stream, logs=rows)

    return send


def make_file_sender(out_path: Path) -> Callable[[list[dict[str, Any]]], None]:
    out_path.parent.mkdir(parents=True, exist_ok=True)

    def send(rows: list[dict[str, Any]]) -> None:
        with out_path.open("a", encoding="utf-8") as fh:
            for row in rows:
                fh.write(json.dumps(row) + "\n")

    return send


class Shipper:
    def __init__(self, log_file: Path, state_file: Path, send: Callable[[list[dict[str, Any]]], None], batch_size: int):
        self.log_file = log_file
        self.state_file = state_file
        self.send = send
        self.batch_size = batch_size
        self.checkpoint = Checkpoint.load(state_file)
        self.stopping = False

    def run_once(self) -> int:
        """Ship everything currently available. Returns the number of events sent."""
        sent = 0
        while not self.stopping:
            lines, new_offset = read_new_lines(self.log_file, self.checkpoint)
            if not lines:
                self.checkpoint.save(self.state_file)
                break
            rows = [row for row in (parse_line(line) for line in lines) if row is not None]
            for start in range(0, len(rows), self.batch_size):
                self._send_with_retry(rows[start : start + self.batch_size])
            self.checkpoint.offset = new_offset
            self.checkpoint.save(self.state_file)
            sent += len(rows)
            log.info("Shipped %d events (offset %d)", len(rows), new_offset)
        return sent

    def _send_with_retry(self, rows: list[dict[str, Any]], attempts: int = 5) -> None:
        delay = 2.0
        for attempt in range(1, attempts + 1):
            try:
                self.send(rows)
                return
            except Exception as exc:  # azure.core.exceptions.* and network errors
                if attempt == attempts or self.stopping:
                    raise
                log.warning("Upload failed (%s); retry %d/%d in %.0fs", exc, attempt, attempts - 1, delay)
                time.sleep(delay)
                delay = min(delay * 2, 60)

    def follow(self, interval: float) -> None:
        while not self.stopping:
            try:
                self.run_once()
            except Exception:
                log.exception("Shipping pass failed; will retry")
            for _ in range(int(interval * 10)):
                if self.stopping:
                    break
                time.sleep(0.1)


def main(argv: list[str] | None = None) -> int:
    load_dotenv()
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--log-file", default=os.getenv("COWRIE_LOG_PATH", "/cowrie/cowrie-git/var/log/cowrie/cowrie.json"))
    parser.add_argument("--state-file", default=os.getenv("SHIPPER_STATE_FILE", "data/state/ship_logs.json"))
    parser.add_argument("--batch-size", type=int, default=500)
    parser.add_argument("--interval", type=float, default=10.0, help="seconds between polls when following")
    parser.add_argument("--once", action="store_true", help="ship what is available and exit")
    parser.add_argument("--from-start", action="store_true", help="ignore the saved checkpoint")
    parser.add_argument("--dry-run", action="store_true", default=os.getenv("SHIPPER_DRY_RUN", "0") == "1",
                        help="append rows to --dry-run-out instead of Azure (env SHIPPER_DRY_RUN=1)")
    parser.add_argument("--dry-run-out", default=os.getenv("SHIPPER_DRY_RUN_OUT", "data/processed/cowrie_rows.jsonl"))
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    if args.dry_run:
        send = make_file_sender(Path(args.dry_run_out))
        log.info("Dry run: writing rows to %s", args.dry_run_out)
    else:
        endpoint = os.getenv("AZURE_DCE_ENDPOINT")
        rule_id = os.getenv("AZURE_DCR_IMMUTABLE_ID")
        if not endpoint or not rule_id:
            log.error("Set AZURE_DCE_ENDPOINT and AZURE_DCR_IMMUTABLE_ID (see .env.example) or use --dry-run")
            return 2
        send = make_azure_sender(endpoint, rule_id, os.getenv("AZURE_DCR_STREAM", DEFAULT_STREAM))

    state_file = Path(args.state_file)
    if args.from_start and state_file.exists():
        state_file.unlink()

    shipper = Shipper(Path(args.log_file), state_file, send, args.batch_size)

    def stop(*_: Any) -> None:
        log.info("Stopping after current batch")
        shipper.stopping = True

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    if args.once:
        total = shipper.run_once()
        log.info("Done: %d events", total)
    else:
        log.info("Following %s", args.log_file)
        shipper.follow(args.interval)
    return 0


if __name__ == "__main__":
    sys.exit(main())
