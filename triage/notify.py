"""Push escalated cases to a chat channel: Microsoft Teams (Workflows webhook) or Slack.

Sentinel incidents are where analysts work; the notification is the tap on the
shoulder for the cases the agent says need a human now. Each case is sent once
(recorded in the SQLite store), with its severity, verdict, sources, rules,
summary, top evidence and next steps.

Everything in the message started as attacker-controlled text (commands, URLs)
or as model output about it. Before sending, IOCs are defanged (``hxxp://``,
``198.51.100[.]23``) - standard SOC practice, and it stops chat clients from
turning an attacker's URL into a clickable link - and markdown link syntax is
broken up so neither the attacker nor the model can plant a link.

    python -m triage.triage_agent --sentinel --watch 10m --notify-webhook https://...
"""

from __future__ import annotations

import logging
import re
from typing import Any

import requests

log = logging.getLogger(__name__)

SEVERITY_ORDER = ["informational", "low", "medium", "high", "critical"]
_SCHEME = re.compile(r"\b(h)tt(ps?)://", re.IGNORECASE)
_URL_HOST = re.compile(r"(hxxps?://)([^/\s:?#]+)", re.IGNORECASE)
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def defang(text: str) -> str:
    """http://198.51.100.23/x -> hxxp://198[.]51[.]100[.]23/x ; bare IPs too; links broken up."""
    text = _SCHEME.sub(r"\1xx\2://", text)
    text = _URL_HOST.sub(lambda m: m.group(1) + m.group(2).replace(".", "[.]"), text)
    text = _IPV4.sub(lambda m: m.group(0).replace(".", "[.]"), text)
    # Break markdown links and Slack <url|text> syntax so nothing becomes clickable.
    return text.replace("](", "] (").replace("<", "‹").replace(">", "›")


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def case_payload(case_id: str, alerts: list[dict[str, Any]], triage: dict[str, Any]) -> dict[str, Any]:
    """Channel-neutral content of one notification, already defanged."""
    ips = sorted({a["src_ip"] for a in alerts})
    return {
        "title": f"[{triage['severity'].upper()}] {triage['verdict']} - {case_id}",
        "severity": triage["severity"],
        "summary": defang(_clip(triage["summary"], 700)),
        "facts": [
            ("Sources", defang(", ".join(ips[:6]) + (f" (+{len(ips) - 6})" if len(ips) > 6 else ""))),
            ("Rules", ", ".join(sorted({a["rule_name"] for a in alerts}))),
            ("Alerts", str(len(alerts))),
            ("Confidence", f"{triage['confidence']:.0%}"),
            ("ATT&CK", ", ".join(t["id"] for t in triage["attack_techniques"]) or "-"),
        ],
        "evidence": [defang(_clip(e, 200)) for e in triage["key_evidence"][:4]],
        "actions": [defang(_clip(a, 200)) for a in triage["recommended_actions"][:4]],
    }


def teams_message(p: dict[str, Any]) -> dict[str, Any]:
    color = {"critical": "Attention", "high": "Attention", "medium": "Warning"}.get(p["severity"], "Default")
    body: list[dict[str, Any]] = [
        {"type": "TextBlock", "text": p["title"], "weight": "Bolder", "size": "Medium", "color": color, "wrap": True},
        {"type": "TextBlock", "text": p["summary"], "wrap": True},
        {"type": "FactSet", "facts": [{"title": k, "value": v} for k, v in p["facts"]]},
    ]
    for heading, items in (("Key evidence", p["evidence"]), ("Recommended actions", p["actions"])):
        if items:
            body.append({"type": "TextBlock", "text": heading, "weight": "Bolder", "spacing": "Medium"})
            body.append({"type": "TextBlock", "text": "\n".join(f"- {i}" for i in items), "wrap": True})
    body.append({"type": "TextBlock", "text": "AI triage of attacker-controlled data - verify before acting.",
                 "isSubtle": True, "size": "Small", "wrap": True})
    card = {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard",
            "version": "1.4", "body": body}
    return {"type": "message",
            "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}]}


def slack_message(p: dict[str, Any]) -> dict[str, Any]:
    fields = [{"type": "mrkdwn", "text": f"*{k}*\n{v}"} for k, v in p["facts"]]
    blocks: list[dict[str, Any]] = [
        {"type": "header", "text": {"type": "plain_text", "text": _clip(p["title"], 150)}},
        {"type": "section", "text": {"type": "mrkdwn", "text": p["summary"]}},
        {"type": "section", "fields": fields[:10]},
    ]
    for heading, items in (("Key evidence", p["evidence"]), ("Recommended actions", p["actions"])):
        if items:
            blocks.append({"type": "section", "text": {"type": "mrkdwn",
                                                       "text": f"*{heading}*\n" + "\n".join(f"• {i}" for i in items)}})
    blocks.append({"type": "context", "elements": [
        {"type": "mrkdwn", "text": "AI triage of attacker-controlled data - verify before acting."}]})
    return {"text": p["title"], "blocks": blocks}


class Notifier:
    def __init__(self, url: str, kind: str | None = None, min_severity: str = "medium", store=None,
                 session: requests.Session | None = None):
        self.url = url
        self.kind = kind or ("slack" if "hooks.slack.com" in url else "teams")
        if self.kind not in ("slack", "teams"):
            raise ValueError("kind must be slack or teams")
        self.min_rank = SEVERITY_ORDER.index(min_severity)
        self.store = store
        self.session = session or requests.Session()

    def wants(self, triage: dict[str, Any] | None) -> bool:
        return bool(triage and triage["escalate"] and SEVERITY_ORDER.index(triage["severity"]) >= self.min_rank)

    def notify_results(self, pairs: list[tuple[dict[str, Any], dict[str, Any]]],
                       results: dict[str, dict[str, Any]]) -> int:
        """Send one message per escalated case not notified before. Returns the number sent."""
        cases: dict[str, list[dict[str, Any]]] = {}
        triages: dict[str, dict[str, Any]] = {}
        for alert, _ in pairs:
            result = results.get(alert["alert_id"]) or {}
            if not self.wants(result.get("triage")):
                continue
            case_id = result.get("case_id") or alert["alert_id"]
            cases.setdefault(case_id, []).append(alert)
            triages[case_id] = result["triage"]
        sent = 0
        for case_id, alerts in cases.items():
            if self.store is not None and self.store.was_notified(case_id):
                continue
            payload = case_payload(case_id, alerts, triages[case_id])
            body = slack_message(payload) if self.kind == "slack" else teams_message(payload)
            try:
                resp = self.session.post(self.url, json=body, timeout=15)
                resp.raise_for_status()
            except requests.RequestException as exc:
                log.error("Notification for %s failed: %s", case_id, exc)
                continue
            if self.store is not None:
                self.store.mark_notified(case_id, self.kind)
            sent += 1
        return sent
