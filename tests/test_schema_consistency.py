"""The parser, the table and the DCR stream must agree on every column, or ingestion silently drops data."""
import json
from pathlib import Path

from ingestion.parsers.cowrie_parser import COLUMNS

INFRA = Path(__file__).resolve().parents[1] / "siem" / "infra"


def _cols(columns):
    return {c["name"]: c["type"] for c in columns}


def test_table_schema_matches_parser():
    table = json.loads((INFRA / "table-schema.json").read_text())
    assert table["properties"]["schema"]["name"] == "Cowrie_CL"
    assert _cols(table["properties"]["schema"]["columns"]) == COLUMNS


def test_dcr_stream_matches_parser():
    template = json.loads((INFRA / "dcr-cowrie.json").read_text())
    dcr = next(r for r in template["resources"] if r["type"] == "Microsoft.Insights/dataCollectionRules")
    stream = dcr["properties"]["streamDeclarations"]["Custom-Cowrie_CL"]
    assert _cols(stream["columns"]) == COLUMNS
    assert dcr["properties"]["dataFlows"][0]["outputStream"] == "Custom-Cowrie_CL"


def test_sample_rows_have_table_columns():
    sample = json.loads((INFRA.parent / "samples" / "cowrie-sample.json").read_text())
    assert sample and all(set(row) == set(COLUMNS) for row in sample)
