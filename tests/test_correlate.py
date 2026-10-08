import pytest

from detections.local_rules import run_all
from triage.correlate import build_cases
from triage.enrich import LocalEventSource, enrich


@pytest.fixture(scope="module")
def pairs(events):
    source = LocalEventSource(events)
    return [(a, enrich(a, source, with_intel=False)) for a in run_all(events)]


def test_cases_never_mix_scenarios(sim, pairs):
    cases = build_cases(pairs)
    assert sum(len(c.alerts) for c in cases) == len(pairs)
    for case in cases:
        assert len({sim.truth[ip].scenario for ip in case.src_ips}) == 1, case.src_ips


def test_campaigns_are_merged_on_shared_infrastructure(sim, pairs):
    cases = build_cases(pairs)
    for scenario, link in [("mirai_botnet", "c2_ip"), ("miner_dropper", "monero_wallet"), ("ssh_key_implant", "ssh_key")]:
        ips = {ip for ip, t in sim.truth.items() if t.scenario == scenario}
        case = next(c for c in cases if set(c.src_ips) & ips)
        assert set(case.src_ips) == ips, scenario
        assert link in {s["type"] for s in case.shared_indicators}


def test_without_infrastructure_links_cases_are_per_ip(pairs):
    cases = build_cases(pairs, link_infrastructure=False)
    assert len(cases) == len({a["src_ip"] for a, _ in pairs})
    assert all(c.shared_indicators == [] for c in cases)


def test_case_ids_are_stable(pairs):
    assert [c.case_id for c in build_cases(pairs)] == [c.case_id for c in build_cases(list(reversed(pairs)))]
