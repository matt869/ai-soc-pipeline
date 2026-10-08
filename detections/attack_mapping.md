# MITRE ATT&CK mapping

Every scheduled detection lives in [`kql/`](kql/). Its header comments (`name`, `severity`, `tactics`, `techniques`, `frequency`, `period`, `description`) are the single source of truth: [`siem/infra/deploy.ps1`](../siem/infra/deploy.ps1) turns them into Sentinel analytics rules, and [`local_rules.py`](local_rules.py) mirrors each query in Python so the pipeline runs offline.

## Detections

| Rule | Severity | Tactic | Technique(s) | Fires on | Schedule |
|---|---|---|---|---|---|
| [01 SSH brute force](kql/01_ssh_bruteforce.kql) | Medium | Credential Access | T1110.001 Password Guessing | >20 failed logins from one IP in a 10-minute bin | every 10 min |
| [02 Payload download command](kql/02_download_command.kql) | High | Command and Control | T1105 Ingress Tool Transfer | `wget`, `curl`, `tftp`, `ftpget` in a session | every 10 min |
| [03 Execution from world-writable dir](kql/03_tmp_execution.kql) | High | Execution, Defense Evasion | T1059.004 Unix Shell, T1222.002 Linux File Permissions Modification | `chmod` on `/tmp`, `/var/tmp`, `/dev/shm` | every 10 min |
| [04 Successful login after brute force](kql/04_success_after_bruteforce.kql) | High | Credential Access, Initial Access | T1110.001, T1078 Valid Accounts | login success from an IP with ≥5 failures in the window | hourly |
| [05 SSH authorized_keys modification](kql/05_ssh_key_persistence.kql) | High | Persistence | T1098.004 SSH Authorized Keys | any command touching `authorized_keys` | every 10 min |
| [06 Host reconnaissance burst](kql/06_system_discovery.kql) | Low | Discovery | T1082 System Information Discovery, T1033 System Owner/User Discovery | ≥3 distinct recon commands (`uname`, `nproc`, `cpuinfo`, `whoami`…) in one session | every 10 min |
| [07 Cryptominer deployment](kql/07_cryptominer.kql) | High | Impact | T1496 Resource Hijacking | miner binaries or pool protocols (`xmrig`, `stratum+tcp`, `--donate-level`…) | every 10 min |

Sentinel's `techniques` field only takes parent IDs, so the deploy script sends `T1110`, `T1059`, and so on. Sub-techniques stay in the KQL header and in the alerts the triage agent sees.

## Coverage of what the honeypot actually sees

| Attacker behaviour | ATT&CK | Covered by |
|---|---|---|
| Password spraying / brute force | T1110.001, T1110.003 | 01, 04 |
| Logging in with default credentials | T1078.001 | 04 (after failures); a first-try default login is only caught by what follows it (02/03/05/06) |
| Fingerprinting the host before deciding what to drop | T1082, T1033, T1057 | 06 |
| Fetching a payload | T1105 | 02, plus `cowrie.session.file_download` in [hunting/captured_payloads.kql](hunting/captured_payloads.kql) |
| Making it executable and running it from /tmp | T1059.004, T1222.002 | 03 |
| Planting an SSH key | T1098.004 | 05 |
| Cron persistence | T1053.003 | not a dedicated rule; visible to the triage agent in session context |
| Changing the root password | T1098 | not a dedicated rule; visible to the triage agent |
| Clearing shell history | T1070.003 | not a dedicated rule; visible to the triage agent |
| Mining | T1496 | 07 |
| Using the sensor as a proxy (direct-tcpip) | T1090 | disabled in [cowrie.cfg](../honeypot/cowrie.cfg) (`forwarding = false`) |

The gaps are deliberate. Cron, password changes and history clearing nearly always follow a download or key plant that already alerted. So the triage agent, which reads the whole session, scores them as part of that alert instead of raising three more.

## Hunting queries

Ad-hoc queries in [`hunting/`](hunting/), not scheduled:

- [top_credentials.kql](hunting/top_credentials.kql): most-tried username/password pairs, and which ones worked.
- [top_commands.kql](hunting/top_commands.kql): the most common post-login commands across sessions.
- [captured_payloads.kql](hunting/captured_payloads.kql): every captured file by SHA-256, ready to pivot into VirusTotal or MalwareBazaar.
- [ssh_client_fingerprints.kql](hunting/ssh_client_fingerprints.kql): HASSH fingerprints shared across many source IPs, which usually means one toolkit or botnet.
- [honeypot_iocs_in_network.kql](hunting/honeypot_iocs_in_network.kql): honeypot-derived IOCs (from the `CowrieIOCs` watchlist, see `triage/iocs.py`) appearing in production firewall, EDR or NSG-flow telemetry.

## Known limitations

- Rule 01 bins by 10 minutes and runs every 10 minutes, so a burst that straddles a run boundary can split into two halves under the threshold. Rule 04 still catches the actor if they get in.
- Rule 04 looks back one hour. Slow, low-volume guessing spread over hours does not trip it.
- Keyword rules (02, 03, 07) match obfuscated commands only if the keyword survives, e.g. not `w''get` or base64-piped scripts. The triage agent sees the raw command text and is told to judge intent, not keywords.
