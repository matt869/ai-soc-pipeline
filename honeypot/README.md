# Honeypot

A [Cowrie](https://github.com/cowrie/cowrie) SSH honeypot on a small Azure VM, plus a log shipper container that streams its events into Sentinel.

| File | Purpose |
|---|---|
| [docker-compose.yml](docker-compose.yml) | Cowrie (port 22 → 2222) and the shipper, sharing Cowrie's log volume read-only |
| [cowrie.cfg](cowrie.cfg) | Overrides: believable hostname/banner, JSON logging, Telnet and TCP forwarding off |
| [userdb.txt](userdb.txt) | Which credentials "work". A short weak list, so bots get a shell and reveal their payloads |
| [Dockerfile.shipper](Dockerfile.shipper) | Minimal image for `ingestion/ship_logs.py` |
| [cloud-init.yaml](cloud-init.yaml) | VM bootstrap: real sshd moves to port 22222, Docker installed |
| [deploy-vm.ps1](deploy-vm.ps1) | Creates the VM, NSG and managed identity |
| [simulate_attacks.py](simulate_attacks.py) | Synthetic Cowrie logs with ground-truth labels, for testing without a live sensor |
| [smoke_test.py](smoke_test.py) | Scripted intrusion against your own sensor, to verify sensor → shipper → detections |

## Deploy to Azure

```powershell
./siem/infra/deploy.ps1                       # workspace, Sentinel, table, DCR (once)
./honeypot/deploy-vm.ps1                      # VM; prints the next commands
./siem/infra/deploy.ps1 -ShipperPrincipalId <printed id>   # let the VM's identity ship logs
```

Then copy the repo to the VM and start the containers, using the `scp` and `ssh` commands `deploy-vm.ps1` prints. The shipper authenticates with the VM's managed identity, so `.env` on the VM only needs `AZURE_DCE_ENDPOINT`, `AZURE_DCR_IMMUTABLE_ID` and `AZURE_DCR_STREAM`.

Check ingestion in Log Analytics after a few minutes:

```kql
Cowrie_CL | summarize count() by eventid
```

## Run locally

```bash
HONEYPOT_PORT=2222 SHIPPER_DRY_RUN=1 docker compose -f honeypot/docker-compose.yml up --build
ssh -p 2222 root@localhost          # password: admin123
docker compose -f honeypot/docker-compose.yml exec shipper tail -f /state/cowrie_rows.jsonl
```

Or let the smoke test play attacker (6 failed passwords, login, recon, a payload fetch from a non-routable TEST-NET address, chmod in /tmp, an SSH-key plant), then run the detections over what the shipper wrote:

```bash
pip install paramiko
python -m honeypot.smoke_test --port 2222
docker compose -f honeypot/docker-compose.yml cp shipper:/state/cowrie_rows.jsonl data/processed/live_rows.jsonl
python -m detections.local_rules data/processed/live_rows.jsonl    # expect rules 02, 03, 04, 05, 06
```

With Docker Desktop (Windows/macOS), connections from your own machine show up as the Docker gateway (`172.x.0.1`), not your IP. On a Linux VM, published ports use iptables DNAT, so Cowrie sees the real attacker address. In Git Bash, prefix `docker compose exec` commands with `MSYS_NO_PATHCONV=1` so `/state/...` is not rewritten to a Windows path.

Stop the stack when you're done (`docker compose ... down`). It listens on all interfaces.

## No sensor yet? Simulate one

```bash
python -m honeypot.simulate_attacks             # data/raw/cowrie_simulated.json + ground_truth.json
```

The simulator produces 10 actor scenarios plus background scanner noise: brute-force bots, a Mirai-style loader, an XMRig dropper with persistence, the "mdrfckr" SSH-key botnet, an egress-check proxy validator, a dropper that tries to prompt-inject the triage agent, authorized internal activity (operator validation, a Nessus scan), and an unknown internal host moving laterally. Attacker IPs come from the RFC 5737 documentation ranges, so no real host is labelled malicious.

## Operating safely

- **Isolation.** The VM has its own VNet. Never peer it with anything, and never reuse its credentials or keys elsewhere.
- **Admin access.** The real sshd listens on 22222, key-only, and the NSG allows it only from your IP. Port 22 belongs to Cowrie.
- **No pivoting.** TCP forwarding is off in `cowrie.cfg`, so attackers can't use the sensor as a proxy.
- **Captured malware.** Payloads land in the `cowrie-var` volume under `lib/cowrie/downloads/`. They are live malware. Hash them, don't run them, and don't download them to your workstation.
- **Container hardening.** Both containers drop all Linux capabilities and set `no-new-privileges`. Cowrie is also memory- and PID-limited.
- **Cost.** A `Standard_B1s` VM plus Log Analytics ingestion for one sensor is typically a few dollars a week. Cowrie logs every keystroke, so set a daily cap on the workspace if the sensor becomes popular.
