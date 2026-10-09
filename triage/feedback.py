"""Analyst feedback: turn human decisions into evaluation data.

The simulated dataset proves the pipeline works; analyst decisions on real
alerts are what show whether the agent can be trusted. This module records
those decisions next to the agent's verdicts in the SQLite store, measures
agreement, and exports them in the evaluation CSV format, so
``python -m evaluation.evaluate --dataset evaluation/feedback_labels.csv`` scores
the current prompt and model against your own analysts.

    # Record a decision by hand (an alert id or a whole case id)
    python -m triage.feedback label case-6f5402ddba --verdict malicious --severity critical --analyst alice

    # Pull decisions from Sentinel: incidents the agent commented on and an analyst then closed
    python -m triage.feedback pull-sentinel --since 7d

    python -m triage.feedback stats
    python -m triage.feedback export --out evaluation/feedback_labels.csv
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from triage.store import Store

ESCALATE_SEVERITIES = {"medium", "high", "critical"}
# Sentinel closing classification -> verdict. Undetermined says nothing about the alert; skip it.
CLASSIFICATION = {"TruePositive": "malicious", "BenignPositive": "benign", "FalsePositive": "benign"}
AI_CLOSE_PREFIX = "Closed by AI triage"


def default_escalate(verdict: str, severity: str | None) -> bool:
    return verdict != "benign" and (severity or "") in ESCALATE_SEVERITIES


def label(store: Store, ref: str, verdict: str, severity: str, escalate: bool | None, analyst: str | None,
          note: str | None) -> list[str]:
    alert_ids = store.alert_ids_for(ref)
    for alert_id in alert_ids:
        store.save_feedback(alert_id, verdict, severity,
                            default_escalate(verdict, severity) if escalate is None else escalate,
                            analyst, "cli", note)
    return alert_ids


def pull_sentinel(store: Store, workspace_resource_id: str, since: timedelta, arm=None) -> dict[str, int]:
    """Import analyst closures of incidents the agent wrote back to."""
    from triage.azure_rest import ArmClient

    arm = arm or ArmClient()
    cutoff = (datetime.now(UTC) - since).strftime("%Y-%m-%dT%H:%M:%SZ")
    incidents = arm.list(f"{workspace_resource_id}/providers/Microsoft.SecurityInsights/incidents", params={
        "$filter": f"properties/status eq 'Closed' and properties/lastModifiedTimeUtc ge {cutoff}",
        "$top": "500",
    })
    counts: Counter[str] = Counter()
    for incident in incidents:
        props = incident.get("properties", {})
        # The store only knows incidents the agent wrote back to, so this also filters to AI-triaged ones.
        alert_ids = store.alerts_for_incident(incident["id"])
        if not alert_ids:
            counts["not triaged by the agent"] += 1
            continue
        if (props.get("classificationComment") or "").startswith(AI_CLOSE_PREFIX):
            counts["closed by the agent itself"] += 1  # not a human decision
            continue
        verdict = CLASSIFICATION.get(props.get("classification", ""))
        if verdict is None:
            counts["undetermined"] += 1
            continue
        severity = (props.get("severity") or "").lower() or None
        analyst = (props.get("owner") or {}).get("userPrincipalName") or (props.get("owner") or {}).get("email")
        note = props.get("classificationComment")
        for alert_id in alert_ids:
            store.save_feedback(alert_id, verdict, severity, default_escalate(verdict, severity), analyst, "sentinel",
                                note)
        counts["imported"] += len(alert_ids)
    return dict(counts)


def agreement(rows: list[dict[str, Any]]) -> dict[str, Any]:
    scored = [r for r in rows if r["ai_verdict"]]
    verdict_ok = sum((r["ai_verdict"] != "benign") == (r["verdict"] != "benign") for r in scored)
    esc_rows = [r for r in scored if r["escalate"] is not None and r["ai_escalate"] is not None]
    escalate_ok = sum(bool(r["ai_escalate"]) == bool(r["escalate"]) for r in esc_rows)
    sev_rows = [r for r in scored if r["severity"] and r["ai_severity"]]
    missed = [r for r in scored if r["verdict"] != "benign" and r["ai_verdict"] == "benign"]
    return {
        "labelled": len(rows),
        "with_ai_verdict": len(scored),
        "verdict_agreement": verdict_ok / len(scored) if scored else None,
        "escalation_agreement": escalate_ok / len(esc_rows) if esc_rows else None,
        "severity_exact": sum(r["severity"] == r["ai_severity"] for r in sev_rows) / len(sev_rows) if sev_rows else None,
        "ai_called_benign_but_analyst_hostile": [r["alert_id"] for r in missed],
        "disagreements": [
            f"{r['alert_id']} ({r['rule_id']}, {r['src_ip']}): analyst {r['verdict']}/{r['severity']}, "
            f"agent {r['ai_verdict']}/{r['ai_severity']}"
            for r in scored if (r["ai_verdict"] != "benign") != (r["verdict"] != "benign")
            or (r["severity"] and r["ai_severity"] and r["severity"] != r["ai_severity"])
        ],
    }


def export(store: Store, out: Path) -> int:
    from evaluation.build_dataset import FIELDS

    rows = [r for r in store.feedback_rows() if r["severity"] and r["enrichment_json"]]
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS)
        writer.writeheader()
        for r in rows:
            escalate = default_escalate(r["verdict"], r["severity"]) if r["escalate"] is None else bool(r["escalate"])
            writer.writerow({
                "alert_id": r["alert_id"], "rule_id": r["rule_id"], "src_ip": r["src_ip"],
                "scenario": f"analyst:{r['source']}", "label_verdict": r["verdict"], "label_severity": r["severity"],
                "label_escalate": str(escalate).lower(), "notes": r["note"] or "",
                "alert_json": r["alert_json"], "context_json": r["enrichment_json"],
            })
    return len(rows)


def _bool(text: str) -> bool:
    if text.lower() in ("yes", "true", "1"):
        return True
    if text.lower() in ("no", "false", "0"):
        return False
    raise argparse.ArgumentTypeError("use yes or no")


def main(argv: list[str] | None = None) -> int:
    from dotenv import load_dotenv

    from triage.triage_agent import parse_duration

    load_dotenv()
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--db", default=os.getenv("TRIAGE_DB", "data/soc.db"))
    sub = parser.add_subparsers(dest="command", required=True)
    p_label = sub.add_parser("label", help="record an analyst decision for an alert or case")
    p_label.add_argument("ref", help="alert id or case id")
    p_label.add_argument("--verdict", required=True, choices=("malicious", "suspicious", "benign"))
    p_label.add_argument("--severity", required=True, choices=("critical", "high", "medium", "low", "informational"))
    p_label.add_argument("--escalate", type=_bool, help="yes/no (default: hostile at medium or above)")
    p_label.add_argument("--analyst")
    p_label.add_argument("--note")
    p_pull = sub.add_parser("pull-sentinel", help="import analyst closures of AI-triaged incidents")
    p_pull.add_argument("--since", type=parse_duration, default=timedelta(days=7))
    sub.add_parser("stats", help="agreement between analysts and the agent")
    p_export = sub.add_parser("export", help="write labels in the evaluation CSV format")
    p_export.add_argument("--out", type=Path, default=Path("evaluation/feedback_labels.csv"))
    args = parser.parse_args(argv)

    store = Store(args.db)
    try:
        if args.command == "label":
            ids = label(store, args.ref, args.verdict, args.severity, args.escalate, args.analyst, args.note)
            if not ids:
                print(f"no stored alert or case '{args.ref}'", file=sys.stderr)
                return 1
            print(f"labelled {len(ids)} alert(s): {', '.join(ids)}")
        elif args.command == "pull-sentinel":
            workspace = os.getenv("AZURE_WORKSPACE_RESOURCE_ID")
            if not workspace:
                print("Set AZURE_WORKSPACE_RESOURCE_ID", file=sys.stderr)
                return 2
            print(json.dumps(pull_sentinel(store, workspace, args.since)))
        elif args.command == "stats":
            print(json.dumps(agreement(store.feedback_rows()), indent=2))
        else:
            n = export(store, args.out)
            print(f"{n} labelled alert(s) -> {args.out}  (python -m evaluation.evaluate --dataset {args.out})")
    finally:
        store.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
