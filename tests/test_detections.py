from collections import defaultdict

import pytest

from detections.local_rules import RULES, _has_term, run_all, ssh_bruteforce
from detections.rules import load_rules

EXPECTED = {
    "bruteforce_only": {"01_ssh_bruteforce"},
    "bruteforce_success_recon": {"01_ssh_bruteforce", "04_success_after_bruteforce", "06_system_discovery"},
    "miner_dropper": {"02_download_command", "03_tmp_execution", "05_ssh_key_persistence", "07_cryptominer"},
    "mirai_botnet": {"02_download_command", "03_tmp_execution"},
    "ssh_key_implant": {"05_ssh_key_persistence"},
    "egress_check": {"02_download_command"},
    "prompt_injection_dropper": {"02_download_command", "03_tmp_execution"},
    "operator_validation": {"02_download_command", "03_tmp_execution"},
    "internal_vuln_scan": {"01_ssh_bruteforce"},
    "internal_lateral": {"01_ssh_bruteforce", "02_download_command", "03_tmp_execution", "04_success_after_bruteforce"},
    "scanner_noise": set(),
}


def test_every_kql_rule_has_metadata_and_a_python_mirror():
    rules = load_rules()
    assert set(rules) == set(RULES)
    for rule in rules.values():
        assert rule.severity in {"Informational", "Low", "Medium", "High"}
        assert all(t.startswith("T1") for t in rule.techniques)
        assert rule.frequency.startswith("PT") and rule.period.startswith("PT")
        assert rule.description


@pytest.fixture(scope="module")
def alerts(events):
    return run_all(events)


def test_rules_fire_per_scenario(sim, alerts):
    fired = defaultdict(set)
    for alert in alerts:
        fired[sim.truth[alert["src_ip"]].scenario].add(alert["rule_id"])
    for scenario, expected in EXPECTED.items():
        assert fired.get(scenario, set()) == expected, scenario


def test_alert_shape_and_unique_ids(alerts):
    assert len({a["alert_id"] for a in alerts}) == len(alerts)
    for alert in alerts:
        assert {"alert_id", "rule_id", "rule_name", "rule_severity", "techniques", "src_ip",
                "first_seen", "last_seen", "evidence"} <= alert.keys()
        assert alert["first_seen"] <= alert["last_seen"]


def _failures(n):
    return [{"eventid": "cowrie.login.failed", "src_ip": "203.0.113.9", "session": "s", "username": "root",
             "TimeGenerated": f"2026-09-01T10:0{i // 10}:{i % 10 * 5:02d}.000000Z"} for i in range(n)]


def test_bruteforce_threshold():
    assert ssh_bruteforce(_failures(20)) == []
    assert len(ssh_bruteforce(_failures(21))) == 1


def test_has_term_matching():
    assert _has_term("cd /tmp; /usr/bin/wget http://x", "wget")
    assert not _has_term("echo wgetrc", "wget")
