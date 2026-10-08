# Sentinel setup

Everything Microsoft Sentinel needs, deployed by one script:

```powershell
az login
./siem/infra/deploy.ps1 -ResourceGroup rg-ai-soc -Location eastus
```

Re-running it updates everything in place. It prints the four `.env` values the shipper and the triage agent need.

## What gets deployed

| Step | Resource | Source |
|---|---|---|
| 1 | Resource group, Log Analytics workspace (90-day retention), Sentinel onboarding | `deploy.ps1` |
| 2 | `Cowrie_CL` custom table | [infra/table-schema.json](infra/table-schema.json) |
| 3 | Data collection endpoint + rule (`Custom-Cowrie_CL` stream) | [infra/dcr-cowrie.json](infra/dcr-cowrie.json) (ARM) |
| 4 | *Monitoring Metrics Publisher* on the DCR, for you and optionally the honeypot VM's managed identity | `deploy.ps1` |
| 5 | One scheduled analytics rule per [detections/kql](../detections/kql) file, with IP entity mapping and incident grouping | `deploy.ps1` (reads the KQL headers) |
| 6 | "Cowrie Honeypot Overview" workbook | [workbooks/honeypot-overview.json](workbooks/honeypot-overview.json) |

Flags:

- `-ShipperPrincipalId <objectId>` grants a managed identity publish rights on the DCR.
- `-TriagePrincipalId <objectId>` grants the triage job's identity *Log Analytics Reader*, *Microsoft Sentinel Responder* (incident comments/updates) and *Microsoft Sentinel Contributor* (needed only to publish the IOC watchlist).
- `-SkipAnalyticsRules` and `-SkipWorkbook` skip steps 5 and 6.

## Data flow

```
cowrie.json ──► ship_logs.py ──HTTPS──► DCE ──► DCR (Custom-Cowrie_CL) ──► Cowrie_CL ──► analytics rules ──► incidents
              (normalizes to the table schema, checkpoints offsets)                       └─► workbook
```

The parser (`ingestion/parsers/cowrie_parser.py`), the table schema and the DCR stream declaration must list the same columns. `tests/test_schema_consistency.py` fails if they drift.

## Testing ingestion without a honeypot

```bash
python -m honeypot.simulate_attacks --out data/raw/sim.json
python -m ingestion.ship_logs --log-file data/raw/sim.json --once
```

Simulated timestamps are in September 2026, so set the Log Analytics time picker to cover that range. [samples/cowrie-sample.json](samples/cowrie-sample.json) holds about 100 normalized rows (three actors). Use it as the sample file if you build the DCR through the portal's "custom log (DCR-based)" wizard instead.

## Workbook

The workbook shows an activity summary, events over time, top source IPs, attacker countries (`geo_info_from_ip_address`), the most-tried credentials, common commands, captured payload hashes, and which Sentinel detections fired.

## IOC watchlist

`python -m triage.iocs --events <log> --upload-watchlist` publishes everything attackers revealed on the honeypot as the `CowrieIOCs` watchlist: attacker IPs, C2 servers, payload URLs and hashes, mining pools and wallets, and planted SSH key fingerprints. [detections/hunting/honeypot_iocs_in_network.kql](../detections/hunting/honeypot_iocs_in_network.kql) then searches firewall/proxy (`CommonSecurityLog`), Defender for Endpoint (`DeviceNetworkEvents`) and NSG flow logs for any internal host that touched that infrastructure. That is how the decoy pays off for the real network. The same run writes a STIX 2.1 bundle for a TIP (MISP, OpenCTI).

## Playbooks

See [playbooks/README.md](playbooks/README.md) for how the triage agent plugs into incident handling.
