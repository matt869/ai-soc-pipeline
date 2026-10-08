"""Enrichment for triage: what else did this source do, who is it, and what does the internet say about it.

Three layers, each optional:

1. **Activity context** from the honeypot's own logs (local events file or Sentinel):
   login attempts, credentials that worked, commands, downloads, client fingerprints.
2. **Asset context** from ``triage/known_assets.json`` for internal addresses.
3. **Threat intel**: AbuseIPDB and GreyNoise Community, cached on disk. Skipped
   for non-routable addresses or when the API keys are not configured.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import time
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

import requests

log = logging.getLogger(__name__)

KNOWN_ASSETS_PATH = Path(__file__).resolve().parent / "known_assets.json"
CACHE_PATH = Path(os.getenv("ENRICHMENT_CACHE", "data/cache/intel.json"))
CACHE_TTL = timedelta(hours=24)
CONTEXT_WINDOW = timedelta(hours=24)
MAX_COMMANDS = 40


class EventSource(Protocol):
    def events_for_ip(self, ip: str, start: datetime, end: datetime) -> list[dict[str, Any]]: ...


class LocalEventSource:
    """Activity lookups against normalized rows already in memory."""

    def __init__(self, events: list[dict[str, Any]]):
        self.by_ip: dict[str, list[dict[str, Any]]] = {}
        for event in events:
            self.by_ip.setdefault(event["src_ip"], []).append(event)

    def events_for_ip(self, ip: str, start: datetime, end: datetime) -> list[dict[str, Any]]:
        lo, hi = _iso(start), _iso(end)
        return [e for e in self.by_ip.get(ip, []) if lo <= e["TimeGenerated"] <= hi]


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


# --- network classification ------------------------------------------------------

_INTERNAL_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10")]


def classify_ip(ip: str) -> dict[str, Any]:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"valid": False}
    internal = any(addr in net for net in _INTERNAL_NETS)
    return {
        "valid": True,
        "internal": internal,
        "globally_routable": addr.is_global,
        "note": "RFC1918/CGNAT address inside our network" if internal
        else None if addr.is_global else "reserved/documentation range (not internet-routable)",
    }


def lookup_asset(ip: str, path: Path = KNOWN_ASSETS_PATH) -> dict[str, Any] | None:
    try:
        inventory = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    addr = ipaddress.ip_address(ip)
    for key, asset in inventory.items():
        if key.startswith("_"):
            continue
        try:
            if addr in ipaddress.ip_network(key, strict=False):
                return asset
        except ValueError:
            continue
    return None


# --- activity summary --------------------------------------------------------------

def summarize_activity(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Condense raw honeypot events for one source into what an analyst needs."""
    if not events:
        return {"events": 0}
    events = sorted(events, key=lambda e: e["TimeGenerated"])
    by_type = Counter(e["eventid"] for e in events)
    failed = [e for e in events if e["eventid"] == "cowrie.login.failed"]
    succeeded = [e for e in events if e["eventid"] == "cowrie.login.success"]
    commands = [e for e in events if e["eventid"] == "cowrie.command.input" and e.get("input")]
    downloads = [e for e in events if e["eventid"] in ("cowrie.session.file_download", "cowrie.session.file_upload")]
    sessions = {e["session"] for e in events if e.get("session")}
    durations = [e["duration"] for e in events if e["eventid"] == "cowrie.session.closed" and e.get("duration") is not None]
    first, last = _parse(events[0]["TimeGenerated"]), _parse(events[-1]["TimeGenerated"])

    return {
        "events": len(events),
        "first_seen": events[0]["TimeGenerated"],
        "last_seen": events[-1]["TimeGenerated"],
        "active_span_minutes": round((last - first).total_seconds() / 60, 1),
        "sessions": len(sessions),
        "event_counts": dict(by_type.most_common()),
        "failed_logins": len(failed),
        "distinct_usernames_tried": len({e.get("username") for e in failed}),
        "top_credentials_tried": [f"{u}/{p}" for (u, p), _ in
                                  Counter((e.get("username"), e.get("password")) for e in failed).most_common(8)],
        "successful_logins": [{"time": e["TimeGenerated"], "session": e["session"],
                               "credential": f"{e.get('username')}/{e.get('password')}"} for e in succeeded][:10],
        "commands": [{"time": e["TimeGenerated"], "session": e["session"], "input": e["input"]}
                     for e in commands][:MAX_COMMANDS],
        "commands_truncated": max(0, len(commands) - MAX_COMMANDS),
        "downloads": [{"url": e.get("url"), "sha256": e.get("shasum")} for e in downloads][:10],
        "client_versions": sorted({e["client_version"] for e in events if e.get("client_version")}),
        "hassh": sorted({e["hassh"] for e in events if e.get("hassh")}),
        "protocols": sorted({e["protocol"] for e in events if e.get("protocol")}),
        "max_session_seconds": max(durations) if durations else None,
    }


# --- threat intel --------------------------------------------------------------------

class IntelCache:
    def __init__(self, path: Path = CACHE_PATH):
        self.path = path
        try:
            self.data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, ValueError):
            self.data = {}

    def get(self, key: str) -> Any | None:
        entry = self.data.get(key)
        if entry and time.time() - entry["fetched"] < CACHE_TTL.total_seconds():
            return entry["value"]
        return None

    def put(self, key: str, value: Any) -> None:
        self.data[key] = {"fetched": time.time(), "value": value}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.data), encoding="utf-8")


def abuseipdb(ip: str, api_key: str, timeout: float = 10) -> dict[str, Any]:
    resp = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        params={"ipAddress": ip, "maxAgeInDays": 90},
        headers={"Key": api_key, "Accept": "application/json"},
        timeout=timeout,
    )
    resp.raise_for_status()
    d = resp.json()["data"]
    return {
        "abuse_confidence_score": d.get("abuseConfidenceScore"),
        "total_reports": d.get("totalReports"),
        "last_reported": d.get("lastReportedAt"),
        "country": d.get("countryCode"),
        "isp": d.get("isp"),
        "usage_type": d.get("usageType"),
        "is_tor": d.get("isTor"),
    }


def greynoise(ip: str, api_key: str | None, timeout: float = 10) -> dict[str, Any]:
    headers = {"Accept": "application/json"}
    if api_key:
        headers["key"] = api_key
    resp = requests.get(f"https://api.greynoise.io/v3/community/{ip}", headers=headers, timeout=timeout)
    if resp.status_code == 404:
        return {"seen": False}
    resp.raise_for_status()
    d = resp.json()
    return {
        "seen": d.get("noise", False),
        "riot": d.get("riot", False),  # common business service (CDN, SaaS...)
        "classification": d.get("classification"),  # benign | malicious | unknown
        "name": d.get("name"),
        "last_seen": d.get("last_seen"),
    }


def threat_intel(ip: str, cache: IntelCache | None = None) -> dict[str, Any]:
    if not classify_ip(ip).get("globally_routable"):
        return {"skipped": "address is not internet-routable"}
    cache = cache or IntelCache()
    results: dict[str, Any] = {}
    sources = {
        "abuseipdb": (os.getenv("ABUSEIPDB_API_KEY"), abuseipdb),
        # GreyNoise Community works without a key: set GREYNOISE_API_KEY to an empty string to enable it keyless.
        "greynoise": (os.getenv("GREYNOISE_API_KEY"), greynoise),
    }
    for name, (key, fn) in sources.items():
        if key is None or (name == "abuseipdb" and not key):
            continue
        cached = cache.get(f"{name}:{ip}")
        if cached is not None:
            results[name] = cached
            continue
        try:
            value = fn(ip, key or None) if name == "greynoise" else fn(ip, key)
            cache.put(f"{name}:{ip}", value)
            results[name] = value
        except (requests.RequestException, KeyError, ValueError) as exc:
            log.warning("%s lookup for %s failed: %s", name, ip, exc)
            results[name] = {"error": str(exc)[:200]}
    return results or {"skipped": "no threat-intel API keys configured"}


# --- entry point ---------------------------------------------------------------------

def enrich(alert: dict[str, Any], source: EventSource | None, with_intel: bool = True,
           cache: IntelCache | None = None) -> dict[str, Any]:
    ip = alert["src_ip"]
    context: dict[str, Any] = {"ip": classify_ip(ip)}
    asset = lookup_asset(ip) if context["ip"].get("valid") else None
    context["known_asset"] = asset or ("no inventory entry for this internal address"
                                       if context["ip"].get("internal") else None)
    if source is not None:
        start = _parse(alert["first_seen"]) - CONTEXT_WINDOW
        end = _parse(alert["last_seen"]) + timedelta(hours=1)
        context["activity_window"] = {"start": _iso(start), "end": _iso(end)}
        context["source_activity"] = summarize_activity(source.events_for_ip(ip, start, end))
    if with_intel:
        context["threat_intel"] = threat_intel(ip, cache)
    return context
