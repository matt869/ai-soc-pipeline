from pathlib import Path

from evaluation.evaluate import baseline_predictions, load_dataset, render_report, score, usage_stats

DATASET = Path(__file__).resolve().parents[1] / "evaluation" / "labeled_alerts.csv"


def test_dataset_is_well_formed():
    rows = load_dataset(DATASET)
    assert len(rows) > 30
    assert {r["label_verdict"] for r in rows} == {"malicious", "benign"}
    assert all(r["alert"]["alert_id"] == r["alert_id"] for r in rows)


def test_dataset_matches_current_simulator_and_rules():
    """Fails if the simulator or rules changed without rebuilding the CSV (python -m evaluation.build_dataset)."""
    from evaluation.build_dataset import build

    assert [r["alert_id"] for r in build(seed=7)] == [r["alert_id"] for r in load_dataset(DATASET)]


def test_baseline_scores():
    rows = load_dataset(DATASET)
    metrics = score(rows, baseline_predictions(rows))
    benign = sum(r["label_verdict"] == "benign" for r in rows)
    assert metrics["verdict"]["fp"] == benign and metrics["verdict"]["fn"] == 0
    assert metrics["escalation"]["queue_reduction"] == 0


def test_perfect_agent_scores_perfectly():
    rows = load_dataset(DATASET)
    preds = {r["alert_id"]: {"triage": {"verdict": r["label_verdict"], "severity": r["label_severity"],
                                        "escalate": r["label_escalate"]},
                             "model_served": "claude-opus-5-5", "latency_ms": 1000,
                             "usage": {"input_tokens": 1000, "output_tokens": 500}} for r in rows}
    metrics = score(rows, preds)
    assert metrics["verdict"]["accuracy"] == 1 and metrics["severity"]["exact"] == 1
    assert metrics["escalation"]["recall"] == 1 and not metrics["misses"]
    usage = usage_stats(preds)
    assert usage["estimated_cost_usd"] == round(len(rows) * (1000 * 4 + 500 * 20) / 1e6, 4)
    report = render_report(DATASET, score(rows, baseline_predictions(rows)), metrics, usage, None)
    assert "LLM triage by scenario" in report


def test_errors_are_excluded_and_counted():
    rows = load_dataset(DATASET)
    metrics = score(rows, {})
    assert metrics["errors"] == len(rows) and metrics["scored"] == 0
