from detections.local_rules import run_all
from triage.enrich import LocalEventSource, classify_ip, enrich, lookup_asset, summarize_activity, threat_intel


def test_classify_ip():
    assert classify_ip("10.0.0.5")["internal"] is True
    assert classify_ip("203.0.113.7")["internal"] is False
    assert classify_ip("203.0.113.7")["globally_routable"] is False
    assert classify_ip("8.8.8.8")["globally_routable"] is True
    assert classify_ip("nope") == {"valid": False}


def test_asset_lookup():
    assert lookup_asset("10.0.0.20")["name"] == "nessus-scan-01"
    assert lookup_asset("10.0.0.47") is None


def test_intel_skipped_for_non_routable():
    assert "skipped" in threat_intel("203.0.113.7")


def test_intel_skipped_without_keys(monkeypatch, tmp_path):
    from triage.enrich import IntelCache

    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.delenv("GREYNOISE_API_KEY", raising=False)
    assert threat_intel("8.8.8.8", IntelCache(tmp_path / "c.json")) == {"skipped": "no threat-intel API keys configured"}


def test_activity_summary_for_miner(sim, events):
    ip = next(ip for ip, t in sim.truth.items() if t.scenario == "miner_dropper")
    summary = summarize_activity([e for e in events if e["src_ip"] == ip])
    assert summary["successful_logins"]
    assert any("xmrig" in c["input"] for c in summary["commands"])
    assert summary["downloads"][0]["sha256"]


def test_enrich_unknown_internal_host(events):
    alert = next(a for a in run_all(events) if a["src_ip"] == "10.0.0.47")
    context = enrich(alert, LocalEventSource(events), with_intel=False)
    assert context["ip"]["internal"]
    assert context["known_asset"] == "no inventory entry for this internal address"
    assert context["source_activity"]["failed_logins"] >= 20
