"""Render triage results as a self-contained HTML analyst queue.

One card per case (or per alert in --mode alert runs), sorted so what needs a
human comes first. Search and verdict filters run client-side, and the file has
no external dependencies, so it can be attached to a ticket or opened offline.

    python -m triage.report                                   # from the SQLite store (data/soc.db)
    python -m triage.report --results data/processed/triage_results.jsonl -o data/processed/report.html
"""

from __future__ import annotations

import argparse
import html
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


def load_records(results: Path | None, db: Path | None) -> list[dict[str, Any]]:
    if results:
        return [json.loads(line) for line in results.read_text(encoding="utf-8").splitlines() if line.strip()]
    from triage.store import Store

    store = Store(db)
    try:
        return list(store.records())
    finally:
        store.close()


def group_cases(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        result = record.get("result") or {}
        groups[result.get("case_id") or record["alert"]["alert_id"]].append(record)
    cases = []
    for case_id, members in groups.items():
        result = next((m["result"] for m in members if (m.get("result") or {}).get("triage")),
                      members[0].get("result") or {})
        alerts = sorted((m["alert"] for m in members), key=lambda a: a["first_seen"])
        cases.append({
            "id": case_id,
            "triage": result.get("triage"),
            "error": result.get("error"),
            "model": result.get("model_served") or result.get("model_requested"),
            "alerts": alerts,
            "ips": sorted({a["src_ip"] for a in alerts}),
            "rules": sorted({a["rule_name"] for a in alerts}),
            "first_seen": alerts[0]["first_seen"],
            "writeback": sorted({m.get("writeback") for m in members if m.get("writeback")}),
        })

    def key(c: dict[str, Any]):
        t = c["triage"]
        if not t:
            return (0, 0, c["first_seen"])  # errors need a human too
        return (1 if t["escalate"] else 2, SEV_ORDER[t["severity"]], c["first_seen"])

    return sorted(cases, key=key)


def _e(value: Any) -> str:
    return html.escape(str(value), quote=True)


def render_case(case: dict[str, Any]) -> str:
    t = case["triage"]
    if t:
        verdict, severity = t["verdict"], t["severity"]
        flag = "escalate" if t["escalate"] else ("benign" if verdict == "benign" else "closed")
        head = (f'<span class="sev sev-{severity}">{_e(severity)}</span>'
                f'<span class="verdict v-{verdict}">{_e(verdict)}</span>'
                f'{"<span class=esc>escalate</span>" if t["escalate"] else ""}'
                f'<span class="conf">{t["confidence"]:.0%} confident</span>')
        summary = f'<p class="summary">{_e(t["summary"])}</p>'
        body = (
            "<div class=cols><div><h4>Key evidence</h4><ul>" + "".join(f"<li>{_e(x)}</li>" for x in t["key_evidence"])
            + "</ul></div><div><h4>Recommended actions</h4><ul>"
            + "".join(f"<li>{_e(x)}</li>" for x in t["recommended_actions"]) + "</ul></div></div>"
            + ("<h4>ATT&amp;CK</h4><p class=tech>" + " ".join(
                f'<a href="https://attack.mitre.org/techniques/{_e(x["id"].replace(".", "/"))}/" target=_blank '
                f'rel=noopener>{_e(x["id"])} {_e(x["name"])}</a>' for x in t["attack_techniques"]) + "</p>"
               if t["attack_techniques"] else "")
        )
    else:
        flag, severity, verdict = "error", "none", "error"
        head = '<span class="sev sev-error">no verdict</span>'
        summary = f'<p class="summary err">{_e(case["error"] or "not triaged")}. Needs manual review.</p>'
        body = ""
    alerts = "".join(
        f"<tr><td>{_e(a['first_seen'][:19].replace('T', ' '))}</td><td>{_e(a['rule_name'])}</td>"
        f"<td>{_e(a['src_ip'])}</td><td><code>{_e(json.dumps(a.get('evidence', {}))[:300])}</code></td></tr>"
        for a in case["alerts"])
    search = " ".join([case["id"], *case["ips"], *case["rules"], t["summary"] if t else ""]).lower()
    meta = f'{len(case["alerts"])} alert(s) · {len(case["ips"])} source(s) · {_e(case["first_seen"][:16].replace("T", " "))} UTC'
    if case["writeback"]:
        meta += " · Sentinel: " + _e(", ".join(case["writeback"]))
    return f"""
<details class="case" data-flag="{flag}" data-sev="{_e(severity)}" data-search="{_e(search)}">
 <summary>
  <div class="row1">{head}<span class="ips">{_e(", ".join(case["ips"][:4]))}{" +" + str(len(case["ips"]) - 4) if len(case["ips"]) > 4 else ""}</span></div>
  <div class="rules">{_e(" · ".join(case["rules"]))}</div>
  {summary}
  <div class="meta">{meta}</div>
 </summary>
 <div class="body">{body}
  <h4>Alerts</h4><table><thead><tr><th>First seen</th><th>Rule</th><th>Source</th><th>Evidence</th></tr></thead><tbody>{alerts}</tbody></table>
  <p class="meta">{_e(case["id"])} · {_e(case["model"] or "")}</p>
 </div>
</details>"""


CSS = """
:root{--bg:#f6f7f9;--card:#fff;--text:#1b1f24;--muted:#5d6672;--line:#dfe3e8;--accent:#2457c5;
--crit:#b3261e;--high:#d1490b;--med:#a86b00;--low:#2f6f4f;--info:#5d6672;--chip:#eef1f5}
@media (prefers-color-scheme:dark){:root{--bg:#111418;--card:#1a1e24;--text:#e6e9ee;--muted:#9aa4b1;--line:#2c323b;
--accent:#7aa2ff;--crit:#ff6b5e;--high:#ff9152;--med:#e3b341;--low:#5cc08a;--info:#9aa4b1;--chip:#252b33}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px 64px}h1{font-size:22px;margin:0 0 4px}.sub{color:var(--muted);margin:0 0 20px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin-bottom:18px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.stat b{display:block;font-size:24px;font-variant-numeric:tabular-nums}.stat span{color:var(--muted);font-size:13px}
.bar{display:flex;height:10px;border-radius:5px;overflow:hidden;margin:0 0 18px;background:var(--chip)}
.bar i{display:block}.controls{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:14px}
.controls button{border:1px solid var(--line);background:var(--card);color:var(--text);border-radius:999px;padding:5px 12px;cursor:pointer;font:inherit;font-size:13px}
.controls button.on{background:var(--accent);border-color:var(--accent);color:#fff}
.controls input{flex:1;min-width:180px;border:1px solid var(--line);background:var(--card);color:var(--text);border-radius:8px;padding:6px 10px;font:inherit}
.case{background:var(--card);border:1px solid var(--line);border-radius:10px;margin-bottom:10px}
.case summary{list-style:none;cursor:pointer;padding:12px 14px}.case summary::-webkit-details-marker{display:none}
.case[data-flag=escalate]{border-left:4px solid var(--crit)}.case[data-flag=error]{border-left:4px solid var(--high)}
.row1{display:flex;flex-wrap:wrap;gap:8px;align-items:center}.ips{margin-left:auto;font-family:ui-monospace,Consolas,monospace;font-size:13px;color:var(--muted)}
.sev,.verdict,.esc{font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.03em;padding:2px 8px;border-radius:5px;background:var(--chip)}
.sev-critical{color:var(--crit)}.sev-high{color:var(--high)}.sev-medium{color:var(--med)}.sev-low{color:var(--low)}.sev-informational{color:var(--info)}.sev-error{color:var(--high)}
.v-malicious{color:var(--crit)}.v-suspicious{color:var(--med)}.v-benign{color:var(--low)}.esc{background:var(--crit);color:#fff}
.conf{font-size:12px;color:var(--muted)}.rules{font-size:13px;color:var(--muted);margin-top:4px}.summary{margin:6px 0 4px}.err{color:var(--high)}
.meta{font-size:12px;color:var(--muted);margin:0}.body{padding:0 14px 14px;border-top:1px solid var(--line)}
.cols{display:grid;grid-template-columns:1fr 1fr;gap:16px}@media (max-width:700px){.cols{grid-template-columns:1fr}.ips{margin-left:0}}
h4{margin:14px 0 4px;font-size:13px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}ul{margin:0;padding-left:18px}
.tech a{display:inline-block;margin:0 6px 6px 0;font-size:13px;color:var(--accent);text-decoration:none;background:var(--chip);padding:2px 8px;border-radius:5px}
table{width:100%;border-collapse:collapse;font-size:13px;display:block;overflow-x:auto}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
td code{font-size:12px;word-break:break-all}.empty{color:var(--muted);text-align:center;padding:40px}
"""

JS = """
const cards=[...document.querySelectorAll('.case')];let flag='all';
function apply(){const q=document.getElementById('q').value.toLowerCase();let n=0;
 cards.forEach(c=>{const ok=(flag==='all'||c.dataset.flag===flag)&&(!q||c.dataset.search.includes(q));c.hidden=!ok;n+=ok});
 document.getElementById('none').hidden=n>0}
document.querySelectorAll('.controls button').forEach(b=>b.onclick=()=>{flag=b.dataset.f;
 document.querySelectorAll('.controls button').forEach(x=>x.classList.toggle('on',x===b));apply()});
document.getElementById('q').oninput=apply;
"""


def render(records: list[dict[str, Any]], title: str = "Honeypot triage queue") -> str:
    cases = group_cases(records)
    triaged = [c for c in cases if c["triage"]]
    flags = Counter("escalate" if c["triage"] and c["triage"]["escalate"] else
                    "error" if not c["triage"] else "benign" if c["triage"]["verdict"] == "benign" else "closed"
                    for c in cases)
    sev = Counter(c["triage"]["severity"] for c in triaged)
    alerts = sum(len(c["alerts"]) for c in cases)
    escalated_alerts = sum(len(c["alerts"]) for c in triaged if c["triage"]["escalate"])
    colors = {"critical": "var(--crit)", "high": "var(--high)", "medium": "var(--med)", "low": "var(--low)",
              "informational": "var(--info)"}
    bar = "".join(f'<i style="width:{100 * sev[s] / max(1, len(triaged)):.1f}%;background:{colors[s]}" '
                  f'title="{s}: {sev[s]}"></i>' for s in SEV_ORDER if sev[s])
    stats = [
        (alerts, "alerts"), (len(cases), "cases"), (flags["escalate"], "cases to escalate"),
        (f"{1 - escalated_alerts / alerts:.0%}" if alerts else "–", "queue reduction"),
        (flags["benign"], "benign cases"), (flags["error"], "need manual review"),
    ]
    buttons = [("all", f"All {len(cases)}"), ("escalate", f"Escalate {flags['escalate']}"),
               ("closed", f"Hostile, no escalation {flags['closed']}"), ("benign", f"Benign {flags['benign']}"),
               ("error", f"No verdict {flags['error']}")]
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_e(title)}</title><style>{CSS}</style></head>
<body><main>
<h1>{_e(title)}</h1><p class="sub">Generated {generated}. Verdicts are produced automatically from attacker-controlled data; verify before acting.</p>
<div class="stats">{"".join(f'<div class="stat"><b>{_e(v)}</b><span>{_e(k)}</span></div>' for v, k in stats)}</div>
<div class="bar" aria-label="cases by severity">{bar}</div>
<div class="controls">{"".join(f'<button data-f="{f}" class="{"on" if f == "all" else ""}">{_e(label)}</button>' for f, label in buttons)}
<input id="q" type="search" placeholder="Search IP, rule, case, summary…"></div>
{"".join(render_case(c) for c in cases)}
<p id="none" class="empty" hidden>No cases match.</p>
</main><script>{JS}</script></body></html>
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--results", type=Path, help="triage JSONL (default: read the SQLite store)")
    parser.add_argument("--db", type=Path, default=Path("data/soc.db"))
    parser.add_argument("-o", "--out", type=Path, default=Path("data/processed/triage_report.html"))
    parser.add_argument("--title", default="Honeypot triage queue")
    args = parser.parse_args(argv)
    records = load_records(args.results, None if args.results else args.db)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(render(records, args.title), encoding="utf-8")
    print(f"{len(records)} alerts -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
