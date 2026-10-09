import csv
import datetime
import json
from types import SimpleNamespace

from evaluation.evaluate import load_dataset, score
from triage.budget import DailyBudget
from triage.feedback import AI_CLOSE_PREFIX, agreement, export, label, pull_sentinel
from triage.pricing import cost_usd
from triage.store import Store
from triage.triage_agent import TriageAgent

ALERT = {"alert_id": "05-a", "rule_id": "05_ssh_key_persistence", "rule_name": "SSH authorized_keys modification",
         "rule_severity": "High", "src_ip": "192.0.2.35", "first_seen": "2026-09-04T07:02:44Z",
         "last_seen": "2026-09-04T07:02:44Z", "evidence": {}}
VERDICT = {"verdict": "malicious", "severity": "high", "confidence": 0.9, "attack_techniques": [],
           "summary": "s", "key_evidence": [], "recommended_actions": [], "escalate": True}


def test_cost_usd():
    assert cost_usd({"input_tokens": 1_000_000, "output_tokens": 0}, "claude-opus-5-5") == 4.0
    # Unknown models are costed at the most expensive known rate.
    assert cost_usd({"output_tokens": 1_000_000}, "some-new-model") == 25.0
    assert cost_usd(None, "claude-opus-5-5") == 0.0


def test_budget_persists_and_rolls_over(tmp_path):
    store = Store(tmp_path / "soc.db")
    day = {"value": "2026-10-09"}
    budget = DailyBudget(0.05, store, clock=lambda: day["value"])
    assert budget.allow()
    budget.record({"output_tokens": 3000}, "claude-opus-5-5")  # $0.06
    assert not budget.allow()
    assert not DailyBudget(0.05, store, clock=lambda: day["value"]).allow()  # survives restarts
    day["value"] = "2026-10-10"
    assert budget.allow()


def test_agent_stops_calling_when_budget_is_spent():
    calls = []

    def create(**params):
        calls.append(params)
        return SimpleNamespace(
            content=[SimpleNamespace(type="text", text=json.dumps(VERDICT))], stop_reason="end_turn",
            model="claude-opus-5-5",
            usage=SimpleNamespace(input_tokens=0, output_tokens=5000, cache_read_input_tokens=0,
                                  cache_creation_input_tokens=0))

    client = SimpleNamespace(beta=SimpleNamespace(messages=SimpleNamespace(create=create)))
    agent = TriageAgent(client=client, system_prompt="S", budget=DailyBudget(0.05), fallbacks=False)
    first = agent.triage(ALERT, {})
    second = agent.triage(ALERT, {})
    assert first["triage"] and len(calls) == 1
    assert second["triage"] is None and "daily budget exhausted" in second["error"]


def stored(tmp_path) -> Store:
    store = Store(tmp_path / "soc.db")
    for i, (ip, ai) in enumerate([("192.0.2.35", "malicious"), ("10.0.0.5", "benign"), ("192.0.2.9", "benign")]):
        alert = {**ALERT, "alert_id": f"05-{i}", "src_ip": ip}
        store.save(alert, {"ip": {"internal": ip.startswith("10.")}},
                   {"alert_id": alert["alert_id"], "case_id": f"case-{i}",
                    "triage": {**VERDICT, "verdict": ai, "escalate": ai != "benign"}})
        store.mark_written_back(alert["alert_id"], "comment", f"/inc/{i}")
    return store


def test_label_agreement_and_export(tmp_path):
    store = stored(tmp_path)
    assert label(store, "case-0", "malicious", "high", None, "alice", None) == ["05-0"]
    label(store, "05-1", "benign", "informational", None, "alice", "operator test")
    label(store, "05-2", "malicious", "medium", None, "bob", "AI missed this")
    assert label(store, "nope", "benign", "low", None, None, None) == []

    stats = agreement(store.feedback_rows())
    assert stats["labelled"] == 3 and abs(stats["verdict_agreement"] - 2 / 3) < 1e-9
    assert stats["ai_called_benign_but_analyst_hostile"] == ["05-2"]

    out = tmp_path / "feedback.csv"
    assert export(store, out) == 3
    rows = load_dataset(out)
    assert {r["scenario"] for r in rows} == {"analyst:cli"}
    assert [r["label_escalate"] for r in rows] == [True, False, True]
    # The exported file is directly usable by the evaluation.
    metrics = score(rows, {r["alert_id"]: {"triage": {"verdict": "malicious", "severity": "high", "escalate": True}}
                           for r in rows})
    assert metrics["scored"] == 3
    with out.open(newline="") as fh:
        assert next(csv.reader(fh))[0] == "alert_id"


class FakeArm:
    def __init__(self, incidents):
        self.incidents = incidents

    def list(self, path, params=None):
        return self.incidents


def incident(i, classification, comment="", severity="High"):
    return {"id": f"/inc/{i}", "properties": {"status": "Closed", "classification": classification,
                                               "classificationComment": comment, "severity": severity,
                                               "owner": {"userPrincipalName": "alice@example.com"}}}


def test_pull_sentinel_imports_only_human_decisions(tmp_path):
    store = stored(tmp_path)
    counts = pull_sentinel(store, "/ws", datetime.timedelta(days=7), arm=FakeArm([
        incident(0, "TruePositive"),
        incident(1, "BenignPositive", comment=f"{AI_CLOSE_PREFIX}: operator validation"),
        incident(2, "Undetermined"),
        incident(9, "FalsePositive"),
    ]))
    assert counts == {"imported": 1, "closed by the agent itself": 1, "undetermined": 1,
                      "not triaged by the agent": 1}
    rows = store.feedback_rows()
    assert [(r["alert_id"], r["verdict"], r["severity"], r["analyst"]) for r in rows] == [
        ("05-0", "malicious", "high", "alice@example.com")]
