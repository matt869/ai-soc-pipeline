"""Generate an ATT&CK Navigator layer from the KQL rule headers.

Open https://mitre-attack.github.io/attack-navigator/ -> "Open Existing Layer" ->
upload detections/attack-navigator-layer.json to see detection coverage, scored
by how many rules cover each technique.

    python -m detections.navigator            # rewrite the layer file
    python -m detections.navigator --check    # exit 1 if it is out of date (CI)
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

from detections.rules import load_rules

LAYER_PATH = Path(__file__).resolve().parent / "attack-navigator-layer.json"
# Navigator tactic short names for the tactics used in the KQL headers.
TACTICS = {
    "CredentialAccess": "credential-access", "InitialAccess": "initial-access", "Execution": "execution",
    "Persistence": "persistence", "DefenseEvasion": "defense-evasion", "Discovery": "discovery",
    "CommandAndControl": "command-and-control", "Impact": "impact",
}


def build_layer() -> dict:
    covered: dict[str, list[str]] = defaultdict(list)
    for rule in load_rules().values():
        for technique in rule.techniques:
            covered[technique].append(f"{rule.rule_id} ({rule.severity})")
    techniques = [
        {"techniqueID": tid, "score": len(rules), "enabled": True, "showSubtechniques": "." in tid,
         "comment": "Detected by: " + ", ".join(sorted(rules))}
        for tid, rules in sorted(covered.items())
    ]
    # Sub-techniques only render under an expanded parent; mark parents so they open.
    parents = {t["techniqueID"].split(".")[0] for t in techniques if "." in t["techniqueID"]}
    for parent in sorted(parents - set(covered)):
        techniques.append({"techniqueID": parent, "enabled": True, "showSubtechniques": True,
                           "comment": "Parent of a covered sub-technique"})
    return {
        "name": "Cowrie honeypot detections",
        "versions": {"attack": "16", "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Coverage of the scheduled KQL analytics rules in ai-soc-pipeline/detections/kql. "
                       "Score = number of rules covering the technique.",
        "filters": {"platforms": ["Linux", "Network Devices", "Containers"]},
        "sorting": 3,
        "layout": {"layout": "side", "showName": True, "showID": True, "hideDisabled": False},
        "hideDisabled": False,
        "techniques": sorted(techniques, key=lambda t: t["techniqueID"]),
        "gradient": {"colors": ["#d9f0d3", "#5aae61", "#1b7837"], "minValue": 0, "maxValue": 3},
        "legendItems": [{"label": "covered by 1 rule", "color": "#d9f0d3"},
                        {"label": "covered by 2+ rules", "color": "#5aae61"}],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "metadata": [{"name": "tactics", "value": ", ".join(sorted({TACTICS[t] for r in load_rules().values()
                                                                   for t in r.tactics if t in TACTICS}))}],
    }


def render() -> str:
    return json.dumps(build_layer(), indent=2) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="fail if the committed layer is stale")
    args = parser.parse_args(argv)
    content = render()
    if args.check:
        current = LAYER_PATH.read_text(encoding="utf-8") if LAYER_PATH.exists() else ""
        if current != content:
            print(f"{LAYER_PATH.name} is out of date: run python -m detections.navigator", file=sys.stderr)
            return 1
        print(f"{LAYER_PATH.name} is up to date")
        return 0
    LAYER_PATH.write_text(content, encoding="utf-8")
    print(f"{len(build_layer()['techniques'])} techniques -> {LAYER_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
