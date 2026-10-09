# Playbooks: connecting triage to Sentinel

The triage agent ([triage/triage_agent.py](../../triage/triage_agent.py)) is a plain Python job. It runs the same KQL detections Sentinel schedules, pulls each source IP's activity from `Cowrie_CL`, and writes one verdict per alert:

```bash
python -m triage.triage_agent --sentinel --lookback 1h --out data/processed/triage_results.jsonl
```

Each output line holds the alert, the enrichment the model saw, and the validated verdict (`verdict`, `severity`, `confidence`, `attack_techniques`, `summary`, `key_evidence`, `recommended_actions`, `escalate`), plus model, token and latency metadata.

## Running it continuously

```bash
python -m triage.triage_agent --sentinel --lookback 1h --watch 10m --writeback comment
```

- **Watch mode** re-runs the detections every interval over the lookback window. The SQLite store (`data/soc.db`) records every verdict, so an alert seen again in the next window is not paid for twice. Failed attempts (API error, refusal) are retried on the next cycle.
- **Cases.** New alerts are grouped by source IP and shared infrastructure, and each case costs one Claude call.
- **Host it** with `docker compose --profile triage up -d` on the honeypot VM: the service runs as the cowrie uid, so it can read captured payloads for static analysis. It also runs as an Azure Container Apps job or anywhere with network access to Azure and the Anthropic API.
- **Daily budget.** `TRIAGE_DAILY_BUDGET_USD` (default 5 in the compose service) stops API calls once the day's estimated spend reaches the cap. Attackers control alert volume, so set a cap. Skipped alerts are stored as "needs manual review" and retried the next UTC day.

It needs:

- `ANTHROPIC_API_KEY`
- `AZURE_LOG_ANALYTICS_WORKSPACE_ID` and `AZURE_WORKSPACE_RESOURCE_ID` (both printed by `deploy.ps1`)
- an identity with the roles `deploy.ps1 -TriagePrincipalId` grants (DefaultAzureCredential: managed identity, `az login`, or service-principal env vars)
- optionally `ABUSEIPDB_API_KEY` / `GREYNOISE_API_KEY`

## Write-back to incidents ([triage/writeback.py](../../triage/writeback.py))

Each alert is matched to its incident by rule title (`Cowrie - <rule name>`), IP entity and creation time. Then, depending on `--writeback`:

| Mode | Effect |
|---|---|
| `comment` (shadow) | Adds the verdict, confidence, summary, key evidence, recommended actions and ATT&CK techniques as an incident comment. The comment id is derived from the alert id, so re-runs update instead of duplicating. |
| `update` | Also sets the incident severity (critical/high → High) and adds `ai-triaged` and `ai-verdict:<verdict>` tags, keeping existing tags. |
| `close` | Also closes incidents judged benign *and* not worth escalating, as *BenignPositive / SuspiciousButExpected*, with the summary as the closing comment. Never reopens or touches closed incidents. |

Recommended rollout: run `comment` for a few weeks and compare the comments with analyst decisions. Move to `update`, then `close`, only when the evaluation numbers ([evaluation/](../../evaluation/)) and the shadow-mode record agree. Filter on the `ai-verdict:benign` tag to audit every auto-closure.

The write-back status of each alert is stored, and shown in the HTML report (`python -m triage.report`).

## Analyst feedback ([triage/feedback.py](../../triage/feedback.py))

When an analyst closes an incident the agent commented on, `python -m triage.feedback pull-sentinel` imports the decision: *TruePositive* → malicious, *BenignPositive*/*FalsePositive* → benign, *Undetermined* → skipped. Closures made by the agent itself (`close` mode) are never imported as human labels. `stats` reports agreement, and lists every alert the agent called benign but an analyst called hostile, which is the number that should gate `close` mode. `export` writes the labels in the evaluation format, so a prompt or model change can be scored against your own analysts' decisions before it ships.

## Guardrails

- Attacker-controlled text (commands, usernames, URLs) reaches the model. The prompt marks it as untrusted, and the simulator includes a prompt-injection scenario so the evaluation measures resistance. Even so, never give the model a tool that can act on infrastructure. It only returns a verdict, and code decides what to do with it.
- The agent never sees secrets. It sees what Cowrie logged, the asset inventory and threat-intel results.
- Refusals and invalid output are recorded as errors with no verdict. Treat them as "needs a human", never as benign.
