"""Score the triage agent against labeled alerts, next to a rule-only baseline.

The baseline is what the SOC gets without the agent: every alert is treated as
malicious, lands in the queue, and keeps the rule's static severity. The agent
earns its place if it closes the benign alerts and the low-value noise without
dropping real intrusions.

    # Run the agent over the dataset (calls the Claude API): one request per correlated case...
    python -m evaluation.evaluate
    # ...or one per alert, to compare cost and accuracy
    python -m evaluation.evaluate --mode alert

    # Re-score saved predictions without calling the API
    python -m evaluation.evaluate --predictions evaluation/results/predictions.jsonl

    # Baseline only
    python -m evaluation.evaluate --baseline-only
"""

from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from triage.pricing import cost_usd

HERE = Path(__file__).resolve().parent
SEVERITIES = ["informational", "low", "medium", "high", "critical"]


def load_dataset(path: Path) -> list[dict[str, Any]]:
    with path.open(newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    for row in rows:
        row["alert"] = json.loads(row["alert_json"])
        row["context"] = json.loads(row["context_json"])
        row["label_escalate"] = row["label_escalate"].strip().lower() == "true"
    return rows


def baseline_predictions(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {
        r["alert_id"]: {"triage": {"verdict": "malicious", "severity": r["alert"]["rule_severity"].lower(),
                                   "escalate": True}}
        for r in rows
    }


def run_agent(rows: list[dict[str, Any]], workers: int, mode: str) -> dict[str, dict[str, Any]]:
    from triage.triage_agent import TriageAgent, triage_pairs

    preds = triage_pairs(TriageAgent(), [(r["alert"], r["context"]) for r in rows], mode, workers)
    for row in rows:
        result = preds[row["alert_id"]]
        status = result["triage"]["verdict"] if result.get("triage") else f"ERROR {result.get('error')}"
        print(f"{row['alert_id']} {result.get('case_id') or '':<16} {row['scenario']}: {status}", file=sys.stderr)
    return preds


def _ratio(num: float, den: float) -> float | None:
    return num / den if den else None


def score(rows: list[dict[str, Any]], preds: dict[str, dict[str, Any]]) -> dict[str, Any]:
    tp = fp = tn = fn = 0  # positive = hostile (malicious/suspicious) vs benign
    esc_tp = esc_fp = esc_fn = escalated = 0
    sev_exact = sev_within_one = 0
    sev_errors: list[int] = []
    scored = errors = 0
    per_scenario: dict[str, dict[str, int]] = defaultdict(
        lambda: {"n": 0, "verdict_ok": 0, "severity_ok": 0, "escalate_ok": 0})
    misses: list[str] = []

    for row in rows:
        result = preds.get(row["alert_id"]) or {}
        t = result.get("triage")
        if not t:
            errors += 1
            continue
        scored += 1
        actual_pos = row["label_verdict"] != "benign"
        pred_pos = t["verdict"] != "benign"
        tp += actual_pos and pred_pos
        fn += actual_pos and not pred_pos
        fp += pred_pos and not actual_pos
        tn += not actual_pos and not pred_pos

        escalated += t["escalate"]
        esc_tp += t["escalate"] and row["label_escalate"]
        esc_fp += t["escalate"] and not row["label_escalate"]
        esc_fn += row["label_escalate"] and not t["escalate"]

        diff = SEVERITIES.index(t["severity"]) - SEVERITIES.index(row["label_severity"])
        sev_errors.append(diff)
        sev_exact += diff == 0
        sev_within_one += abs(diff) <= 1

        s = per_scenario[row["scenario"]]
        s["n"] += 1
        s["verdict_ok"] += pred_pos == actual_pos
        s["severity_ok"] += diff == 0
        s["escalate_ok"] += t["escalate"] == row["label_escalate"]
        if pred_pos != actual_pos or t["escalate"] != row["label_escalate"]:
            misses.append(f"{row['alert_id']} ({row['scenario']}, {row['rule_id']}): labelled "
                          f"{row['label_verdict']}/{row['label_severity']}/escalate={row['label_escalate']}, "
                          f"got {t['verdict']}/{t['severity']}/escalate={t['escalate']}")

    precision, recall = _ratio(tp, tp + fp), _ratio(tp, tp + fn)
    esc_precision, esc_recall = _ratio(esc_tp, esc_tp + esc_fp), _ratio(esc_tp, esc_tp + esc_fn)
    return {
        "alerts": len(rows),
        "scored": scored,
        "errors": errors,
        "verdict": {
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "accuracy": _ratio(tp + tn, scored),
            "precision": precision,
            "recall": recall,
            "f1": _ratio(2 * precision * recall, precision + recall) if precision and recall else None,
            "benign_suppressed": _ratio(tn, tn + fp),
        },
        "escalation": {
            "escalated": escalated,
            "queue_reduction": _ratio(scored - escalated, scored),
            "precision": esc_precision,
            "recall": esc_recall,
            "missed_escalations": esc_fn,
        },
        "severity": {
            "exact": _ratio(sev_exact, scored),
            "within_one": _ratio(sev_within_one, scored),
            "mean_abs_error": statistics.mean(abs(d) for d in sev_errors) if sev_errors else None,
            "mean_signed_error": statistics.mean(sev_errors) if sev_errors else None,
        },
        "per_scenario": dict(sorted(per_scenario.items())),
        "misses": misses,
    }


def usage_stats(preds: dict[str, dict[str, Any]]) -> dict[str, Any]:
    latencies = [p["latency_ms"] for p in preds.values() if p.get("latency_ms") is not None and p.get("triage")]
    totals = defaultdict(int)
    cost = 0.0
    served: dict[str, int] = defaultdict(int)
    for p in preds.values():
        usage = p.get("usage") or {}
        for key, value in usage.items():
            totals[key] += value or 0
        model = p.get("model_served") or p.get("model_requested")
        if model:
            served[model] += 1
        cost += cost_usd(usage, model)
    lat_sorted = sorted(latencies)
    return {
        "api_calls": len({p.get("case_id") or alert_id for alert_id, p in preds.items()}),
        "models_served": dict(served),
        "latency_p50_ms": statistics.median(lat_sorted) if lat_sorted else None,
        "latency_p95_ms": lat_sorted[min(len(lat_sorted) - 1, int(0.95 * len(lat_sorted)))] if lat_sorted else None,
        "tokens": dict(totals),
        "estimated_cost_usd": round(cost, 4),
        "cost_per_alert_usd": round(cost / len(preds), 4) if preds else None,
    }


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.0%}"


def render_report(dataset: Path, base: dict[str, Any], agent: dict[str, Any] | None, usage: dict[str, Any] | None,
                  predictions_path: Path | None) -> str:
    cols = [("Rule-only baseline", base)] + ([("LLM triage", agent)] if agent else [])
    header = "| Metric | " + " | ".join(name for name, _ in cols) + " |\n|---|" + "---|" * len(cols) + "\n"

    def line(label: str, fn) -> str:
        return f"| {label} | " + " | ".join(fn(m) for _, m in cols) + " |\n"

    out = [f"# Triage evaluation\n\nDataset: `{dataset.name}`, {base['alerts']} alerts. "
           f"Generated {datetime.now(UTC):%Y-%m-%d %H:%M} UTC.\n"]
    if predictions_path:
        out.append(f"Predictions: `{predictions_path.as_posix()}`.\n")
    out.append("\n## Verdict (hostile vs benign)\n\n" + header)
    out.append(line("Alerts scored", lambda m: f"{m['scored']}/{m['alerts']}"))
    out.append(line("Accuracy", lambda m: _pct(m["verdict"]["accuracy"])))
    out.append(line("Precision", lambda m: _pct(m["verdict"]["precision"])))
    out.append(line("Recall (hostile caught)", lambda m: _pct(m["verdict"]["recall"])))
    out.append(line("F1", lambda m: _pct(m["verdict"]["f1"])))
    out.append(line("Benign alerts closed", lambda m: _pct(m["verdict"]["benign_suppressed"])))
    out.append(line("TP / FP / TN / FN", lambda m: "{tp} / {fp} / {tn} / {fn}".format(**m["verdict"])))
    out.append("\n## Analyst queue\n\n" + header)
    out.append(line("Alerts escalated", lambda m: str(m["escalation"]["escalated"])))
    out.append(line("Queue reduction", lambda m: _pct(m["escalation"]["queue_reduction"])))
    out.append(line("Escalation precision", lambda m: _pct(m["escalation"]["precision"])))
    out.append(line("Escalation recall", lambda m: _pct(m["escalation"]["recall"])))
    out.append(line("Missed escalations", lambda m: str(m["escalation"]["missed_escalations"])))
    out.append("\n## Severity\n\n" + header)
    out.append(line("Exact match", lambda m: _pct(m["severity"]["exact"])))
    out.append(line("Within one level", lambda m: _pct(m["severity"]["within_one"])))
    out.append(line("Mean abs. error (levels)", lambda m: f"{m['severity']['mean_abs_error']:.2f}"
                    if m["severity"]["mean_abs_error"] is not None else "n/a"))
    out.append(line("Mean signed error (+ = over-rated)", lambda m: f"{m['severity']['mean_signed_error']:+.2f}"
                    if m["severity"]["mean_signed_error"] is not None else "n/a"))

    if agent:
        out.append("\n## LLM triage by scenario\n\n"
                   "| Scenario | Alerts | Verdict correct | Escalation correct | Severity exact |\n|---|---|---|---|---|\n")
        for name, s in agent["per_scenario"].items():
            n = s["n"]
            out.append(f"| {name} | {n} | {s['verdict_ok']}/{n} | {s['escalate_ok']}/{n} | {s['severity_ok']}/{n} |\n")
        if usage:
            out.append("\n## Cost and latency\n\n")
            out.append(f"- API calls: {usage['api_calls']} for {agent['alerts']} alerts\n")
            out.append(f"- Models served: {', '.join(f'{k} ({v})' for k, v in usage['models_served'].items())}\n")
            out.append(f"- Latency p50 / p95: {usage['latency_p50_ms']} ms / {usage['latency_p95_ms']} ms\n")
            out.append(f"- Tokens: {json.dumps(usage['tokens'])}\n")
            out.append(f"- Estimated cost: ${usage['estimated_cost_usd']} total, ${usage['cost_per_alert_usd']} per alert "
                       "(list prices; cached reads at the cache rate)\n")
        if agent["misses"]:
            out.append("\n## Disagreements with the labels\n\n" + "".join(f"- {m}\n" for m in agent["misses"]))
        if agent["errors"]:
            out.append(f"\n{agent['errors']} alert(s) returned no verdict (API error, refusal or invalid output); "
                       "they are excluded from the metrics above.\n")
    return "".join(out)


def main(argv: list[str] | None = None) -> int:
    load_dotenv()
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dataset", default=str(HERE / "labeled_alerts.csv"))
    parser.add_argument("--predictions", help="score saved predictions (JSONL) instead of calling the API")
    parser.add_argument("--baseline-only", action="store_true")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--mode", choices=("case", "alert"), default="case",
                        help="one request per correlated case (default) or per alert")
    parser.add_argument("--results-dir", default=str(HERE / "results"))
    parser.add_argument("--report", help="markdown report path (default: <results-dir>/report.md)")
    args = parser.parse_args(argv)

    dataset = Path(args.dataset)
    rows = load_dataset(dataset)[: args.limit] if args.limit else load_dataset(dataset)
    results_dir = Path(args.results_dir)
    results_dir.mkdir(parents=True, exist_ok=True)

    base = score(rows, baseline_predictions(rows))
    agent_metrics = usage = None
    predictions_path: Path | None = None
    if not args.baseline_only:
        if args.predictions:
            predictions_path = Path(args.predictions)
            preds = {}
            for line in predictions_path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    record = json.loads(line)
                    preds[record["alert_id"]] = record
        else:
            preds = run_agent(rows, args.workers, args.mode)
            predictions_path = results_dir / f"predictions-{args.mode}-{datetime.now(UTC):%Y%m%dT%H%M%SZ}.jsonl"
            predictions_path.write_text("".join(json.dumps(p) + "\n" for p in preds.values()), encoding="utf-8")
        agent_metrics = score(rows, preds)
        usage = usage_stats({k: v for k, v in preds.items() if k in {r["alert_id"] for r in rows}})

    report = render_report(dataset, base, agent_metrics, usage, predictions_path)
    report_path = Path(args.report) if args.report else results_dir / "report.md"
    report_path.write_text(report, encoding="utf-8")
    (results_dir / "metrics.json").write_text(
        json.dumps({"baseline": base, "agent": agent_metrics, "usage": usage}, indent=2), encoding="utf-8")
    print(report)
    print(f"Report -> {report_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
