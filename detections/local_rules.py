"""Python mirror of the KQL detections, for running the pipeline without Azure.

Each function reproduces the logic of the KQL file with the same id over a list
of normalized Cowrie_CL rows (see ingestion/parsers/cowrie_parser.py) and emits
alerts in the same shape that triage/sentinel.py builds from Log Analytics
results. Rule metadata (name, severity, ATT&CK ids) comes from the KQL headers.

Differences from KQL are deliberate approximations: ``has`` term matching is
emulated with an alphanumeric-boundary regex, and rule 04 counts failures in the
hour before each success instead of across the whole query period.

    python -m detections.local_rules siem/samples/cowrie-sample.json
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Callable, Iterable

from detections.rules import load_rules

Event = dict[str, Any]
Alert = dict[str, Any]


def _ts(event: Event) -> datetime:
    return datetime.fromisoformat(event["TimeGenerated"].replace("Z", "+00:00"))


def _has_term(text: str, term: str) -> bool:
    """Approximate KQL ``has``: whole-term, case-insensitive match."""
    return re.search(rf"(?<![A-Za-z0-9]){re.escape(term)}(?![A-Za-z0-9])", text, re.IGNORECASE) is not None


def _contains(text: str, needle: str) -> bool:
    return needle.lower() in text.lower()


def make_alert_id(rule_id: str, *key_parts: Any) -> str:
    digest = hashlib.sha1("|".join([rule_id, *map(str, key_parts)]).encode()).hexdigest()
    return f"{rule_id.split('_', 1)[0]}-{digest[:10]}"


def build_alert(rule_id: str, src_ip: str, session: str | None, first_seen: str, last_seen: str,
                evidence: dict[str, Any], key: Iterable[Any] | None = None) -> Alert:
    rule = load_rules()[rule_id]
    key_parts = list(key) if key is not None else [src_ip, session, first_seen]
    return {
        "alert_id": make_alert_id(rule_id, *key_parts),
        "rule_id": rule_id,
        "rule_name": rule.name,
        "rule_description": rule.description,
        "rule_severity": rule.severity,
        "tactics": list(rule.tactics),
        "techniques": list(rule.techniques),
        "src_ip": src_ip,
        "session": session,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "evidence": evidence,
    }


def _commands(events: list[Event]) -> list[Event]:
    return [e for e in events if e["eventid"] == "cowrie.command.input" and e.get("input")]


def _per_session(rule_id: str, matches: list[Event]) -> list[Alert]:
    grouped: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for event in matches:
        grouped[(event["src_ip"], event["session"])].append(event)
    alerts = []
    for (src_ip, session), group in grouped.items():
        group.sort(key=lambda e: e["TimeGenerated"])
        alerts.append(build_alert(
            rule_id, src_ip, session, group[0]["TimeGenerated"], group[-1]["TimeGenerated"],
            {"Commands": [e["input"] for e in group][:25]},
            key=[src_ip, session],
        ))
    return alerts


def ssh_bruteforce(events: list[Event]) -> list[Alert]:
    windows: dict[tuple[str, datetime], list[Event]] = defaultdict(list)
    for event in events:
        if event["eventid"] == "cowrie.login.failed":
            ts = _ts(event)
            window = ts.replace(minute=ts.minute - ts.minute % 10, second=0, microsecond=0)
            windows[(event["src_ip"], window)].append(event)
    alerts = []
    for (src_ip, window), group in windows.items():
        if len(group) <= 20:
            continue
        users = sorted({e["username"] for e in group if e.get("username")})
        alerts.append(build_alert(
            "01_ssh_bruteforce", src_ip, None,
            min(e["TimeGenerated"] for e in group), max(e["TimeGenerated"] for e in group),
            {"Attempts": len(group), "DistinctUsers": len(users), "SampleUsers": users[:10],
             "Window": window.isoformat().replace("+00:00", "Z")},
            key=[src_ip, window.isoformat()],
        ))
    return alerts


def download_command(events: list[Event]) -> list[Alert]:
    tools = ("wget", "curl", "tftp", "ftpget")
    return _per_session("02_download_command",
                        [e for e in _commands(events) if any(_has_term(e["input"], t) for t in tools)])


def tmp_execution(events: list[Event]) -> list[Alert]:
    return _per_session("03_tmp_execution", [
        e for e in _commands(events)
        if _has_term(e["input"], "chmod") and any(_contains(e["input"], d) for d in ("/tmp", "/var/tmp", "/dev/shm"))
    ])


def success_after_bruteforce(events: list[Event]) -> list[Alert]:
    failures: dict[str, list[datetime]] = defaultdict(list)
    for event in events:
        if event["eventid"] == "cowrie.login.failed":
            failures[event["src_ip"]].append(_ts(event))
    alerts = []
    seen_sessions = set()
    for event in events:
        if event["eventid"] != "cowrie.login.success" or event["session"] in seen_sessions:
            continue
        ts = _ts(event)
        prior = [f for f in failures.get(event["src_ip"], []) if ts - timedelta(hours=1) <= f < ts]
        if len(prior) >= 5:
            seen_sessions.add(event["session"])
            alerts.append(build_alert(
                "04_success_after_bruteforce", event["src_ip"], event["session"],
                event["TimeGenerated"], event["TimeGenerated"],
                {"Username": event.get("username"), "Password": event.get("password"), "FailedAttempts": len(prior)},
                key=[event["src_ip"], event["session"]],
            ))
    return alerts


def ssh_key_persistence(events: list[Event]) -> list[Alert]:
    return _per_session("05_ssh_key_persistence",
                        [e for e in _commands(events) if _contains(e["input"], "authorized_keys")])


RECON_TERMS = ("uname", "cpuinfo", "meminfo", "nproc", "lscpu", "lspci", "whoami", "hostname", "uptime",
               "ifconfig", "crontab", "netstat", "getconf", "dmidecode")


def system_discovery(events: list[Event]) -> list[Alert]:
    sessions: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for event in _commands(events):
        sessions[(event["src_ip"], event["session"])].append(event)
    alerts = []
    for (src_ip, session), group in sessions.items():
        indicators = sorted({t for e in group for t in RECON_TERMS if _has_term(e["input"], t)})
        if len(indicators) < 3:
            continue
        matching = [e for e in group if any(_has_term(e["input"], t) for t in indicators)]
        alerts.append(build_alert(
            "06_system_discovery", src_ip, session, matching[0]["TimeGenerated"], matching[-1]["TimeGenerated"],
            {"Indicators": indicators, "Commands": list(dict.fromkeys(e["input"] for e in matching))[:25]},
            key=[src_ip, session],
        ))
    return alerts


MINER_MARKERS = ("xmrig", "minerd", "cpuminer", "stratum+tcp", "stratum+ssl", "donate-level", "c3pool",
                 "moneroocean", "nanopool")


def cryptominer(events: list[Event]) -> list[Alert]:
    return _per_session("07_cryptominer",
                        [e for e in _commands(events) if any(_contains(e["input"], m) for m in MINER_MARKERS)])


RULES: dict[str, Callable[[list[Event]], list[Alert]]] = {
    "01_ssh_bruteforce": ssh_bruteforce,
    "02_download_command": download_command,
    "03_tmp_execution": tmp_execution,
    "04_success_after_bruteforce": success_after_bruteforce,
    "05_ssh_key_persistence": ssh_key_persistence,
    "06_system_discovery": system_discovery,
    "07_cryptominer": cryptominer,
}


def run_all(events: list[Event]) -> list[Alert]:
    events = sorted(events, key=lambda e: e["TimeGenerated"])
    alerts = [alert for rule in RULES.values() for alert in rule(events)]
    return sorted(alerts, key=lambda a: (a["first_seen"], a["rule_id"]))


if __name__ == "__main__":
    import argparse
    import sys

    from ingestion.parsers.cowrie_parser import load_events

    parser = argparse.ArgumentParser(description="Run the detection rules locally over a Cowrie log.")
    parser.add_argument("path", help="cowrie.json, normalized rows (JSONL), or a JSON array")
    parser.add_argument("-o", "--out", help="write alerts as JSON lines here (default: stdout)")
    args = parser.parse_args()

    found = run_all(load_events(args.path))
    out = open(args.out, "w", encoding="utf-8") if args.out else sys.stdout
    for alert in found:
        out.write(json.dumps(alert) + "\n")
    if args.out:
        out.close()
    counts: dict[str, int] = defaultdict(int)
    for alert in found:
        counts[alert["rule_id"]] += 1
    print(f"{len(found)} alerts: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())), file=sys.stderr)
