"""Build evaluation/labeled_alerts.csv from simulated honeypot traffic.

Runs the simulator, the local detections and the (offline) enrichment, then
labels each alert with the ground truth of the scenario that produced it. The
enrichment is frozen into the CSV so evaluation runs are reproducible and do not
need the event log or any threat-intel keys.

Labels are per source IP: every alert raised by one actor shares that actor's
verdict and overall severity. ``label_escalate`` is true for malicious activity
at medium severity or above.

To evaluate on real data instead, produce alerts with ``detections.local_rules``
or ``triage.sentinel``, then fill in the label columns by hand.

    python -m evaluation.build_dataset
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from detections.local_rules import run_all
from honeypot.simulate_attacks import simulate
from ingestion.parsers.cowrie_parser import parse_event
from triage.enrich import LocalEventSource, enrich

FIELDS = ["alert_id", "rule_id", "src_ip", "scenario", "label_verdict", "label_severity", "label_escalate",
          "notes", "alert_json", "context_json"]
ESCALATE_SEVERITIES = {"medium", "high", "critical"}


def build(seed: int) -> list[dict[str, str]]:
    sim = simulate(seed)
    events = sorted((parse_event(e) for e in sim.events), key=lambda e: e["TimeGenerated"])
    source = LocalEventSource(events)
    rows = []
    for alert in run_all(events):
        truth = sim.truth[alert["src_ip"]]
        context = enrich(alert, source, with_intel=False)
        rows.append({
            "alert_id": alert["alert_id"],
            "rule_id": alert["rule_id"],
            "src_ip": alert["src_ip"],
            "scenario": truth.scenario,
            "label_verdict": truth.verdict,
            "label_severity": truth.severity,
            "label_escalate": str(truth.verdict == "malicious" and truth.severity in ESCALATE_SEVERITIES).lower(),
            "notes": truth.description,
            "alert_json": json.dumps(alert, separators=(",", ":")),
            "context_json": json.dumps(context, separators=(",", ":")),
        })
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--out", default=str(Path(__file__).resolve().parent / "labeled_alerts.csv"))
    args = parser.parse_args()

    rows = build(args.seed)
    with open(args.out, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    benign = sum(r["label_verdict"] == "benign" for r in rows)
    print(f"{len(rows)} labeled alerts ({benign} benign, {len(rows) - benign} malicious) -> {args.out}")


if __name__ == "__main__":
    main()
