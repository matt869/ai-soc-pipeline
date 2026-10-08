import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


@pytest.fixture(scope="session")
def sim():
    from honeypot.simulate_attacks import simulate

    return simulate(seed=7)


@pytest.fixture(scope="session")
def events(sim):
    from ingestion.parsers.cowrie_parser import parse_event

    return sorted((parse_event(e) for e in sim.events), key=lambda e: e["TimeGenerated"])
