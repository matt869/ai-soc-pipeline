# AI SOC Pipeline

A Cowrie SSH honeypot feeding Microsoft Sentinel, with ATT&CK-mapped KQL detections and an LLM triage step (Claude). Triage groups alerts into cases (one actor, or a whole campaign sharing infrastructure), decides how bad each case is and whether a human needs to see it, and writes the verdict back to the Sentinel incident. Everything the attackers revealed is exported as IOCs to hunt for in the production network. An evaluation harness measures the triage against a rule-only baseline.

```
Cowrie ─► ship_logs.py ─► DCE/DCR ─► Cowrie_CL ─► KQL analytics rules ─► incidents ◄── comment / severity / close ──┐
                                        │                                                                         │
                                        ├─► triage: enrich ─► correlate into cases ─► Claude ─► verdicts ─► SQLite store ─► HTML queue
                                        │
                                        └─► IOCs (C2, payload hashes, wallets, SSH keys) ─► STIX / watchlist ─► hunt production logs
```

Details: [architecture](docs/architecture.md) · [writeup](docs/writeup.md) · [ATT&CK mapping](detections/attack_mapping.md)

## Repository layout

| Path | What's there |
|---|---|
| [honeypot/](honeypot/) | Cowrie Docker setup, hardened config, Azure VM deploy, attack simulator |
| [ingestion/](ingestion/) | Cowrie JSON parser and the log shipper (Logs Ingestion API, checkpointed) |
| [siem/](siem/) | Table schema, DCE/DCR template, `deploy.ps1`, workbook, playbook notes, sample data |
| [detections/](detections/) | 7 scheduled KQL rules, 5 hunting queries (incl. honeypot IOCs in production logs), Python mirror of the rules, ATT&CK mapping |
| [triage/](triage/) | Enrichment, campaign correlation, the Claude triage agent and prompt, SQLite store, Sentinel write-back, IOC export, HTML report |
| [evaluation/](evaluation/) | Labelled alerts built from simulator ground truth; scoring vs a rule-only baseline |
| [tests/](tests/) | 56 tests: parser, schema consistency, rules, shipper, enrichment, IOCs, correlation, agent, store, write-back, report, metrics |
| [.github/workflows/ci.yml](.github/workflows/ci.yml) | Tests, an offline pipeline run, PowerShell parsing and template validation on every push |

## Quick start (offline, no Azure needed)

```bash
python -m venv .venv && .venv/Scripts/activate      # source .venv/bin/activate on Linux/macOS
pip install -r requirements.txt
cp .env.example .env                               # add ANTHROPIC_API_KEY for the triage steps

python -m pytest -q                                          # tests
python -m honeypot.simulate_attacks                          # synthetic Cowrie log + ground truth
python -m detections.local_rules data/raw/cowrie_simulated.json -o data/processed/alerts.jsonl
python -m triage.triage_agent --events data/raw/cowrie_simulated.json --limit 1 --dry-run   # inspect a request
python -m triage.triage_agent --events data/raw/cowrie_simulated.json                       # 44 alerts in 18 cases
python -m triage.report                                      # analyst queue -> data/processed/triage_report.html
python -m triage.iocs --events data/raw/cowrie_simulated.json   # IOCs -> CSV + STIX 2.1
python -m evaluation.evaluate                                # LLM vs baseline -> evaluation/results/report.md
python -m evaluation.evaluate --mode alert                   # same, one request per alert, to compare cost
```

### Run the real sensor locally

```bash
HONEYPOT_PORT=2222 SHIPPER_DRY_RUN=1 docker compose -f honeypot/docker-compose.yml up -d --build
python -m honeypot.smoke_test --port 2222          # scripted intrusion against your own sensor
docker compose -f honeypot/docker-compose.yml cp shipper:/state/cowrie_rows.jsonl data/processed/live_rows.jsonl
python -m detections.local_rules data/processed/live_rows.jsonl
docker compose -f honeypot/docker-compose.yml down
```

## Full deployment (Azure)

```powershell
az login
./siem/infra/deploy.ps1                 # workspace + Sentinel + table + DCR + rules + workbook; prints .env values
./honeypot/deploy-vm.ps1                # honeypot VM; prints the copy/start commands and its identity
./siem/infra/deploy.ps1 -ShipperPrincipalId <vm identity> -TriagePrincipalId <vm identity>   # ship logs + run triage
```

Then run triage continuously against Sentinel. It skips alerts it already triaged, and starts in shadow mode, which only adds a comment to each incident:

```bash
python -m triage.triage_agent --sentinel --lookback 1h --watch 10m --writeback comment
python -m triage.iocs --events <exported log> --triage-results data/processed/triage_results.jsonl --upload-watchlist
```

Move to `--writeback update` (severity + tags), then `close` (auto-close benign), once the evaluation and a shadow-mode period support it.

See [honeypot/README.md](honeypot/README.md) for operating the sensor safely, and [siem/README.md](siem/README.md) for what each deployment step creates.

## Configuration

All settings live in `.env` ([.env.example](.env.example)). The triage agent defaults to `claude-opus-5-5` at effort `medium`, with server-side refusal fallbacks enabled (`TRIAGE_FALLBACKS=default`). Threat-intel lookups run only when their keys are set, and only for internet-routable IPs.

## Requirements

Python 3.11+. For deployment: Azure CLI 2.50+ and PowerShell 5.1+ or 7. For the sensor: Docker with Compose v2.
