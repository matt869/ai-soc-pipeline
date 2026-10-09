"""Portable detections must stay in sync with the KQL headers (the source of truth)."""
from pathlib import Path

import pytest
import yaml

from detections.navigator import LAYER_PATH, build_layer, render
from detections.rules import load_rules

SIGMA_DIR = Path(__file__).resolve().parents[1] / "detections" / "sigma"
LEVEL = {"Informational": "informational", "Low": "low", "Medium": "medium", "High": "high"}


def sigma_docs(rule_id):
    path = SIGMA_DIR / f"{rule_id}.yml"
    assert path.exists(), f"missing Sigma rule for {rule_id}"
    return list(yaml.safe_load_all(path.read_text(encoding="utf-8")))


@pytest.mark.parametrize("rule_id", sorted(load_rules()))
def test_sigma_matches_kql_header(rule_id):
    rule = load_rules()[rule_id]
    final = sigma_docs(rule_id)[-1]  # the alerting rule is last; earlier documents are building blocks
    assert final["title"] == rule.name
    assert final["level"] == LEVEL[rule.severity]
    tags = set(final["tags"])
    assert {f"attack.{t.lower()}" for t in rule.techniques} <= tags
    assert f"detections/kql/{rule_id}.kql" in final["description"]


def test_sigma_ids_are_unique():
    ids = [doc["id"] for f in SIGMA_DIR.glob("*.yml") for doc in yaml.safe_load_all(f.read_text(encoding="utf-8"))]
    assert len(ids) == len(set(ids))


def test_sigma_parses_with_pysigma():
    collection = pytest.importorskip("sigma.collection")
    for path in SIGMA_DIR.glob("*.yml"):
        rules = collection.SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))
        rules.resolve_rule_references()
        assert all(not getattr(r, "errors", []) for r in rules), path.name


def test_navigator_layer_is_current():
    assert LAYER_PATH.read_text(encoding="utf-8") == render(), "run: python -m detections.navigator"
    scores = {t["techniqueID"]: t.get("score") for t in build_layer()["techniques"]}
    assert scores["T1110.001"] == 2  # rules 01 and 04
    assert all(scores[t] for r in load_rules().values() for t in r.techniques)
