"""Extract indicators of compromise from honeypot activity.

Everything an attacker types into the honeypot is intelligence about their
infrastructure: payload URLs, C2 addresses, file hashes, mining wallets and
pools, the SSH keys they plant. This module pulls those out deterministically
(no LLM), and exports them as

* a CSV (also the content of a Sentinel watchlist, ``CowrieIOCs``),
* a STIX 2.1 bundle for TIPs / MISP / OpenCTI,

so detections on the *production* network can hunt for infrastructure first
seen on the decoy (see detections/hunting/honeypot_iocs_in_network.kql).

    python -m triage.iocs --events data/raw/cowrie_simulated.json --out-dir data/processed/iocs
    python -m triage.iocs --events ... --triage-results data/processed/triage_results.jsonl --upload-watchlist
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import ipaddress
import json
import re
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

# Indicator types. attacker_ip = a source that connected; everything else came out of what it typed.
LINKING_TYPES = {"c2_ip", "url", "domain", "sha256", "monero_wallet", "ssh_key", "mining_pool"}

# IP-echo and test services attackers use to check egress. Not malicious infrastructure.
BENIGN_HOSTS = {
    "ifconfig.me", "ipinfo.io", "api.ipify.org", "icanhazip.com", "checkip.amazonaws.com", "ifconfig.co",
    "example.com", "google.com", "www.google.com", "1.1.1.1", "8.8.8.8",
}

_URL = re.compile(r"\b(?:https?|ftp|tftp)://[^\s'\"<>;|)`]+", re.IGNORECASE)
_POOL = re.compile(r"\bstratum\+(?:tcp|ssl|tls)://([^\s'\"<>;|)`]+)", re.IGNORECASE)
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_WALLET = re.compile(r"\b[48][1-9A-HJ-NP-Za-km-z]{94}\b")
_SSH_KEY = re.compile(r"\b(ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-nistp\d+)\s+(AAAA[0-9A-Za-z+/=]{8,})(?:\s+([^\s\"'>]+))?")
_INTERNAL = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
                                               "127.0.0.0/8", "0.0.0.0/8", "169.254.0.0/16")]


def _is_external_ip(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return addr.version == 4 and not any(addr in net for net in _INTERNAL) and not addr.is_multicast


def ssh_key_fingerprint(blob_b64: str) -> str:
    """OpenSSH-style SHA256 fingerprint of a public key blob."""
    try:
        raw = base64.b64decode(blob_b64 + "=" * (-len(blob_b64) % 4), validate=False)
    except (ValueError, TypeError):
        raw = blob_b64.encode()
    return "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")


def extract_from_text(text: str) -> list[tuple[str, str, str]]:
    """Return (type, value, note) triples found in one attacker-controlled string."""
    found: list[tuple[str, str, str]] = []
    url_spans = []
    for match in _URL.finditer(text):
        url = match.group(0).rstrip(".,")
        url_spans.append(match.span())
        host = (urlsplit(url).hostname or "").lower()
        if not host or host in BENIGN_HOSTS:
            continue
        found.append(("url", url, "payload or C2 URL"))
        if _is_external_ip(host):
            found.append(("c2_ip", host, "server in a URL"))
        elif not _IPV4.fullmatch(host):
            found.append(("domain", host, "host in a URL"))
    for match in _POOL.finditer(text):
        found.append(("mining_pool", match.group(1).rstrip(".,"), "stratum mining pool"))
    for match in _IPV4.finditer(text):
        if any(start <= match.start() < end for start, end in url_spans):
            continue  # already handled as a URL host
        ip = match.group(0)
        if _is_external_ip(ip) and ip not in BENIGN_HOSTS:
            found.append(("c2_ip", ip, "address in a command (tftp/nc/wget without scheme)"))
    for match in _WALLET.finditer(text):
        found.append(("monero_wallet", match.group(0), "Monero wallet"))
    for match in _SSH_KEY.finditer(text):
        note = f"planted {match.group(1)} key" + (f" (comment '{match.group(3)}')" if match.group(3) else "")
        found.append(("ssh_key", ssh_key_fingerprint(match.group(2)), note))
    return found


@dataclass
class Indicator:
    type: str
    value: str
    description: str
    first_seen: str
    last_seen: str
    sightings: int = 0
    source_ips: set[str] = field(default_factory=set)
    sessions: set[str] = field(default_factory=set)

    def to_row(self) -> dict[str, Any]:
        return {
            "Indicator": self.value, "Type": self.type, "FirstSeen": self.first_seen, "LastSeen": self.last_seen,
            "Sightings": self.sightings, "SourceIPs": " ".join(sorted(self.source_ips)[:10]),
            "Description": self.description,
        }


class IndicatorSet:
    def __init__(self) -> None:
        self._items: dict[tuple[str, str], Indicator] = {}

    def add(self, type_: str, value: str, note: str, ts: str, src_ip: str | None, session: str | None) -> None:
        key = (type_, value)
        ind = self._items.get(key)
        if ind is None:
            ind = self._items[key] = Indicator(type_, value, note, ts, ts)
        ind.first_seen, ind.last_seen = min(ind.first_seen, ts), max(ind.last_seen, ts)
        ind.sightings += 1
        if src_ip:
            ind.source_ips.add(src_ip)
        if session:
            ind.sessions.add(session)

    def __iter__(self):
        return iter(sorted(self._items.values(), key=lambda i: (i.type, i.value)))

    def __len__(self) -> int:
        return len(self._items)


def iocs_from_events(events: Iterable[dict[str, Any]], exclude_sources: set[str] | None = None,
                     attacker_ips: set[str] | None = None) -> IndicatorSet:
    """Indicators from raw Cowrie_CL rows.

    ``attacker_ips``: sources to publish as attacker_ip indicators (defaults to every
    external source that logged in or ran commands). ``exclude_sources``: ignore
    everything these sources did, e.g. IPs whose activity was triaged as benign.
    """
    exclude_sources = exclude_sources or set()
    out = IndicatorSet()
    active: set[str] = set()
    for event in events:
        ip, ts, session = event.get("src_ip"), event["TimeGenerated"], event.get("session")
        if ip in exclude_sources:
            continue
        if event["eventid"] in ("cowrie.login.success", "cowrie.command.input"):
            active.add(ip)
        texts = []
        if event["eventid"] == "cowrie.command.input" and event.get("input"):
            texts.append(event["input"])
        if event["eventid"] in ("cowrie.session.file_download", "cowrie.session.file_upload"):
            if event.get("url"):
                texts.append(event["url"])
            if event.get("shasum"):
                out.add("sha256", event["shasum"], "file captured by the honeypot", ts, ip, session)
        for text in texts:
            for type_, value, note in extract_from_text(text):
                out.add(type_, value, note, ts, ip, session)
    for event in events:
        ip = event.get("src_ip")
        wanted = attacker_ips if attacker_ips is not None else active
        if ip in wanted and ip not in exclude_sources and _is_external_ip(ip or ""):
            out.add("attacker_ip", ip, "source that logged in to / attacked the honeypot", event["TimeGenerated"], ip,
                    event.get("session"))
    return out


def indicators_from_context(alert: dict[str, Any], context: dict[str, Any]) -> set[tuple[str, str]]:
    """Linking indicators (type, value) visible in one alert and its enrichment. Used for correlation."""
    texts: list[str] = []
    evidence = alert.get("evidence") or {}
    for value in evidence.values():
        if isinstance(value, list):
            texts.extend(str(v) for v in value)
        elif isinstance(value, str):
            texts.append(value)
    activity = context.get("source_activity") or {}
    texts.extend(c["input"] for c in activity.get("commands", []))
    found = {(t, v) for text in texts for t, v, _ in extract_from_text(text)}
    for download in activity.get("downloads", []):
        if download.get("sha256"):
            found.add(("sha256", download["sha256"]))
        if download.get("url"):
            found.update((t, v) for t, v, _ in extract_from_text(download["url"]))
    return {(t, v) for t, v in found if t in LINKING_TYPES}


# --- exports ---------------------------------------------------------------------------

def to_csv(indicators: IndicatorSet) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=["Indicator", "Type", "FirstSeen", "LastSeen", "Sightings", "SourceIPs",
                                             "Description"], lineterminator="\n")
    writer.writeheader()
    for ind in indicators:
        writer.writerow(ind.to_row())
    return buf.getvalue()


_STIX_NS = uuid.UUID("6f7f3b1e-4c1a-4b55-9f3a-0c5b8d2e7a10")
_STIX_PATTERNS = {
    "attacker_ip": "[ipv4-addr:value = '{v}']",
    "c2_ip": "[ipv4-addr:value = '{v}']",
    "url": "[url:value = '{v}']",
    "domain": "[domain-name:value = '{v}']",
    "sha256": "[file:hashes.'SHA-256' = '{v}']",
    "mining_pool": "[network-traffic:dst_ref.value = '{host}' AND network-traffic:dst_port = {port}]",
    "monero_wallet": "[x-cryptocurrency-wallet:address = '{v}']",
    "ssh_key": "[x-ssh-key:fingerprint = '{v}']",
}
_STIX_TYPES = {"attacker_ip": ["malicious-activity"], "c2_ip": ["malicious-activity"], "url": ["malicious-activity"],
               "domain": ["malicious-activity"], "sha256": ["malicious-activity"], "mining_pool": ["malicious-activity"],
               "monero_wallet": ["attribution"], "ssh_key": ["attribution"]}


def _stix_time(ts: str) -> str:
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def to_stix(indicators: IndicatorSet, producer: str = "ai-soc-pipeline honeypot") -> dict[str, Any]:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    identity_id = f"identity--{uuid.uuid5(_STIX_NS, producer)}"
    objects: list[dict[str, Any]] = [{
        "type": "identity", "spec_version": "2.1", "id": identity_id, "created": now, "modified": now,
        "name": producer, "identity_class": "system",
    }]
    for ind in indicators:
        value = ind.value.replace("\\", "\\\\").replace("'", "\\'")
        if ind.type == "mining_pool":
            host, _, port = ind.value.partition(":")
            if not port.isdigit():
                continue
            pattern = _STIX_PATTERNS["mining_pool"].format(host=host.replace("'", "\\'"), port=port)
        else:
            pattern = _STIX_PATTERNS[ind.type].format(v=value)
        objects.append({
            "type": "indicator", "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid5(_STIX_NS, ind.type + '|' + ind.value)}",
            "created": now, "modified": now, "created_by_ref": identity_id,
            "name": f"{ind.type}: {ind.value[:80]}", "description": ind.description,
            "indicator_types": _STIX_TYPES[ind.type], "pattern": pattern, "pattern_type": "stix",
            "valid_from": _stix_time(ind.first_seen), "labels": ["honeypot", "cowrie", ind.type],
            "x_sightings": ind.sightings, "x_last_seen": _stix_time(ind.last_seen),
        })
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


def upload_watchlist(csv_text: str, workspace_resource_id: str, alias: str = "CowrieIOCs", arm=None) -> None:
    """Create or replace a Sentinel watchlist whose rows are the indicators (search key: Indicator)."""
    from triage.azure_rest import ArmClient

    arm = arm or ArmClient()
    path = f"{workspace_resource_id}/providers/Microsoft.SecurityInsights/watchlists/{alias}"
    # Replacing content in place is not supported for local-file watchlists: delete, then recreate.
    arm.request("DELETE", path, ok=(200, 204, 404))
    arm.request("PUT", path, body={"properties": {
        "displayName": "Cowrie honeypot IOCs",
        "description": "Infrastructure observed on the Cowrie honeypot (ai-soc-pipeline/triage/iocs.py)",
        "provider": "ai-soc-pipeline",
        "source": "honeypot-iocs.csv",
        "itemsSearchKey": "Indicator",
        "contentType": "text/csv",
        "numberOfLinesToSkip": 0,
        "rawContent": csv_text,
    }})


def benign_sources(triage_results: Path) -> tuple[set[str], set[str]]:
    """(sources only ever judged benign, sources judged hostile at least once) from triage output."""
    verdicts: dict[str, set[str]] = defaultdict(set)
    for line in triage_results.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        result = (record.get("result") or {}).get("triage")
        if result:
            verdicts[record["alert"]["src_ip"]].add(result["verdict"])
    benign = {ip for ip, v in verdicts.items() if v == {"benign"}}
    return benign, set(verdicts) - benign


def main(argv: list[str] | None = None) -> int:
    import os

    from dotenv import load_dotenv

    from ingestion.parsers.cowrie_parser import load_events

    load_dotenv()
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--events", required=True, help="Cowrie log (raw or normalized)")
    parser.add_argument("--triage-results", help="drop sources triaged as benign; publish only hostile attacker IPs")
    parser.add_argument("--out-dir", default="data/processed/iocs")
    parser.add_argument("--upload-watchlist", action="store_true", help="publish as Sentinel watchlist CowrieIOCs")
    args = parser.parse_args(argv)

    exclude, hostile = (benign_sources(Path(args.triage_results)) if args.triage_results else (set(), None))
    indicators = iocs_from_events(load_events(args.events), exclude_sources=exclude, attacker_ips=hostile)
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    csv_text = to_csv(indicators)
    (out / "iocs.csv").write_text(csv_text, encoding="utf-8")
    (out / "iocs.stix.json").write_text(json.dumps(to_stix(indicators), indent=1), encoding="utf-8")
    counts: dict[str, int] = defaultdict(int)
    for ind in indicators:
        counts[ind.type] += 1
    print(f"{len(indicators)} indicators ({', '.join(f'{k}={v}' for k, v in sorted(counts.items()))}) -> {out}")
    if exclude:
        print(f"excluded {len(exclude)} source(s) triaged as benign: {', '.join(sorted(exclude))}")
    if args.upload_watchlist:
        workspace = os.getenv("AZURE_WORKSPACE_RESOURCE_ID")
        if not workspace:
            print("Set AZURE_WORKSPACE_RESOURCE_ID to upload the watchlist")
            return 2
        upload_watchlist(csv_text, workspace)
        print("uploaded Sentinel watchlist CowrieIOCs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
