"""Write triage verdicts back to the matching Microsoft Sentinel incidents.

Modes, from least to most trust in the agent:

* ``comment``: add the verdict, evidence and next steps as an incident comment (shadow mode).
* ``update``: also set the incident severity and add ``ai-triaged`` / ``ai-verdict:<verdict>`` tags.
* ``close``: also close incidents the agent judged benign and not worth escalating, as
  *BenignPositive*. Only use this once evaluation and a shadow-mode period support it.

An alert maps to an incident through the analytics rule title (``Cowrie - <rule name>``,
as created by siem/infra/deploy.ps1), the IP entity, and the creation time.
Comments get a deterministic id per alert, so re-running never duplicates them.
"""

from __future__ import annotations

import html
import logging
import uuid
from datetime import datetime, timedelta
from typing import Any

from triage.azure_rest import ArmClient

log = logging.getLogger(__name__)

MODES = ("comment", "update", "close")
SENTINEL_SEVERITY = {"critical": "High", "high": "High", "medium": "Medium", "low": "Low",
                     "informational": "Informational"}
_NS = uuid.UUID("0b8f4c1e-2f6d-4c8e-9a51-7e3d2b1f6a42")


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def format_comment(alert: dict[str, Any], result: dict[str, Any]) -> str:
    t = result["triage"]
    esc = "<b>ESCALATE</b>" if t["escalate"] else "no escalation needed"
    lines = [
        f"<p><b>AI triage</b> ({html.escape(result.get('model_served') or result.get('model_requested', ''))}): "
        f"<b>{t['verdict'].upper()}</b>, severity <b>{t['severity']}</b>, confidence {t['confidence']:.0%}, {esc}</p>",
        f"<p>{html.escape(t['summary'])}</p>",
        "<p><b>Key evidence</b></p><ul>" + "".join(f"<li>{html.escape(e)}</li>" for e in t["key_evidence"]) + "</ul>",
        "<p><b>Recommended actions</b></p><ul>" + "".join(f"<li>{html.escape(a)}</li>" for a in t["recommended_actions"])
        + "</ul>",
    ]
    if t["attack_techniques"]:
        lines.append("<p>ATT&amp;CK: " + ", ".join(html.escape(f"{x['id']} {x['name']}") for x in t["attack_techniques"])
                     + "</p>")
    if result.get("case_id"):
        lines.append(f"<p>Case {html.escape(result['case_id'])}; alert {html.escape(alert['alert_id'])}.</p>")
    lines.append("<p><i>Generated automatically from attacker-controlled log data. Verify before acting.</i></p>")
    return "".join(lines)


class SentinelWriter:
    def __init__(self, workspace_resource_id: str, mode: str = "comment", arm: ArmClient | None = None):
        if mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}")
        self.base = f"{workspace_resource_id}/providers/Microsoft.SecurityInsights"
        self.mode = mode
        self.arm = arm or ArmClient()
        self._incidents: dict[str, list[dict[str, Any]]] = {}
        self._entities: dict[str, set[str]] = {}
        self.last_incident_id: str | None = None  # incident matched by the latest apply(), for the store

    def _candidates(self, title: str, since: datetime) -> list[dict[str, Any]]:
        key = f"{title}|{since:%Y-%m-%d}"
        if key not in self._incidents:
            title_q = title.replace("'", "''")
            self._incidents[key] = self.arm.list(f"{self.base}/incidents", params={
                "$filter": f"properties/title eq '{title_q}' and properties/createdTimeUtc ge "
                           f"{since:%Y-%m-%dT00:00:00Z}",
                "$orderby": "properties/createdTimeUtc asc",
                "$top": "200",
            })
        return self._incidents[key]

    def _ips(self, incident_id: str) -> set[str]:
        if incident_id not in self._entities:
            data = self.arm.request("POST", f"{incident_id}/entities")
            self._entities[incident_id] = {
                e.get("properties", {}).get("address") for e in data.get("entities", []) if e.get("kind") == "Ip"
            }
        return self._entities[incident_id]

    def find_incident(self, alert: dict[str, Any]) -> dict[str, Any] | None:
        first_seen = _parse(alert["first_seen"])
        title = f"Cowrie - {alert['rule_name']}"
        for incident in self._candidates(title, first_seen - timedelta(hours=1)):
            created = _parse(incident["properties"]["createdTimeUtc"])
            if created >= first_seen - timedelta(minutes=5) and alert["src_ip"] in self._ips(incident["id"]):
                return incident
        return None

    def apply(self, alert: dict[str, Any], result: dict[str, Any]) -> str:
        """Returns a short status string for the store (e.g. 'comment', 'closed', 'no-incident')."""
        self.last_incident_id = None
        if not result.get("triage"):
            return "skipped-no-verdict"
        incident = self.find_incident(alert)
        if incident is None:
            return "no-incident"
        self.last_incident_id = incident["id"]
        comment_id = uuid.uuid5(_NS, alert["alert_id"])
        self.arm.request("PUT", f"{incident['id']}/comments/{comment_id}",
                         body={"properties": {"message": format_comment(alert, result)}})
        status = "comment"
        if self.mode in ("update", "close"):
            status = self._update(incident, result["triage"])
        log.info("%s -> incident %s: %s", alert["alert_id"], incident["name"], status)
        return status

    def _update(self, incident: dict[str, Any], t: dict[str, Any]) -> str:
        current = self.arm.request("GET", incident["id"])
        props = current["properties"]
        if props.get("status") == "Closed":
            return "comment (incident already closed)"
        labels = [lbl for lbl in props.get("labels", []) if not lbl["labelName"].startswith("ai-")]
        labels += [{"labelName": "ai-triaged", "labelType": "User"},
                   {"labelName": f"ai-verdict:{t['verdict']}", "labelType": "User"}]
        new_props = {
            "title": props["title"],
            "description": props.get("description", ""),
            "severity": SENTINEL_SEVERITY[t["severity"]],
            "status": props["status"],
            "labels": labels,
            "owner": props.get("owner", {}),
        }
        status = "updated"
        if self.mode == "close" and t["verdict"] == "benign" and not t["escalate"]:
            new_props.update({
                "status": "Closed",
                "classification": "BenignPositive",
                "classificationReason": "SuspiciousButExpected",
                "classificationComment": f"Closed by AI triage: {t['summary'][:900]}",
            })
            status = "closed"
        self.arm.request("PUT", incident["id"], body={"etag": current.get("etag"), "properties": new_props})
        return status
