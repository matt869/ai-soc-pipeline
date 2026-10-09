"""Static triage of payloads the honeypot captured.

Cowrie saves every file an attacker downloads under ``var/lib/cowrie/downloads/<sha256>``.
This module reads those files (it never executes them) and summarizes what they are:

* file type: ELF (architecture, 32/64-bit, endianness), shell script, archive, PE
* packing (UPX) and family hints from embedded strings (Mirai-style busybox/watchdog
  handling, miner configs, SSH persistence, log wiping)
* IOCs embedded in the binary's strings (C2 hosts, URLs, wallets, pools)
* optional reputation by hash: MalwareBazaar (``MALWAREBAZAAR_API_KEY``) and
  VirusTotal (``VT_API_KEY``), cached like the IP intel

The result goes into the triage enrichment so the model can tell "downloaded a
Mirai ARM build" from "downloaded something", and into the IOC feed.

    python -m triage.payloads /var/lib/docker/volumes/ai-soc-honeypot_cowrie-var/_data/lib/cowrie/downloads
    python -m triage.payloads <dir-or-files> --lookup      # add hash reputation
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import struct
from pathlib import Path
from typing import Any

import requests

from triage.iocs import extract_from_text

log = logging.getLogger(__name__)

MAX_READ = 20 * 1024 * 1024
ELF_MACHINES = {2: "sparc", 3: "x86", 4: "m68k", 8: "mips", 20: "powerpc", 21: "powerpc64", 40: "arm",
                42: "superh", 62: "x86-64", 183: "aarch64", 243: "riscv"}
FAMILY_MARKERS: dict[str, tuple[str, ...]] = {
    "mirai-like (busybox/watchdog handling)": ("/dev/watchdog", "/dev/misc/watchdog", "/bin/busybox"),
    "cryptominer": ("xmrig", "stratum+tcp", "stratum+ssl", "donate-level", "randomx", "cryptonight"),
    "ssh key persistence": ("authorized_keys",),
    "cron persistence": ("crontab", "/etc/cron"),
    "log/history wiping": ("history -c", "/var/log/wtmp", "/var/log/lastlog", "unset HISTFILE"),
    "competitor killing": ("pkill -9", "killall -9", "/proc/net/tcp"),
    "downloader": ("wget ", "curl ", "tftp ", "ftpget "),
    "ddos": ("udpflood", "synflood", "ackflood", "HTTPFLOOD", "attack_"),
}
_STRINGS = re.compile(rb"[\x20-\x7e]{6,}")


def _file_type(head: bytes) -> dict[str, Any]:
    if head[:4] == b"\x7fELF" and len(head) >= 20:
        bits = {1: 32, 2: 64}.get(head[4])
        endian = {1: "little", 2: "big"}.get(head[5], "little")
        machine = struct.unpack("<H" if endian == "little" else ">H", head[18:20])[0]
        return {"type": "elf", "arch": ELF_MACHINES.get(machine, f"machine-{machine}"), "bits": bits,
                "endianness": endian}
    if head[:2] == b"#!":
        return {"type": "script", "interpreter": head[2:].split(b"\n", 1)[0].strip().decode(errors="replace")[:60]}
    if head[:2] == b"\x1f\x8b":
        return {"type": "gzip"}
    if head[:4] == b"PK\x03\x04":
        return {"type": "zip"}
    if len(head) > 262 and head[257:262] == b"ustar":
        return {"type": "tar"}
    if head[:2] == b"MZ":
        return {"type": "pe"}
    if head and all(32 <= b < 127 or b in (9, 10, 13) for b in head[:512]):
        return {"type": "text"}
    return {"type": "unknown"}


def analyze_bytes(data: bytes) -> dict[str, Any]:
    info: dict[str, Any] = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data), **_file_type(data[:4096])}
    strings = [m.group(0).decode("ascii") for m in _STRINGS.finditer(data[:MAX_READ])][:20000]
    blob = "\n".join(strings)
    lowered = blob.lower()
    info["packed_upx"] = b"UPX!" in data
    info["family_hints"] = sorted(name for name, markers in FAMILY_MARKERS.items()
                                  if any(m.lower() in lowered for m in markers))
    iocs: dict[tuple[str, str], None] = {}
    for line in strings:
        for type_, value, _ in extract_from_text(line):
            iocs.setdefault((type_, value), None)
    info["embedded_iocs"] = [{"type": t, "value": v} for t, v in list(iocs)[:30]]
    markers = [m.lower() for ms in FAMILY_MARKERS.values() for m in ms]
    info["notable_strings"] = [s[:160] for s in strings if any(m in s.lower() for m in markers)][:15]
    return info


def analyze_file(path: str | Path) -> dict[str, Any]:
    path = Path(path)
    with path.open("rb") as fh:
        data = fh.read(MAX_READ + 1)
    info = analyze_bytes(data[:MAX_READ])
    info["truncated"] = len(data) > MAX_READ
    return info


def find_payload(sha256: str, payload_dir: str | Path | None) -> Path | None:
    if not payload_dir or not re.fullmatch(r"[0-9a-f]{64}", sha256 or ""):
        return None  # never build paths from anything but a clean hash
    candidate = Path(payload_dir) / sha256
    return candidate if candidate.is_file() else None


# --- reputation ------------------------------------------------------------------------

def malwarebazaar(sha256: str, api_key: str, timeout: float = 15) -> dict[str, Any]:
    resp = requests.post("https://mb-api.abuse.ch/api/v1/", data={"query": "get_info", "hash": sha256},
                         headers={"Auth-Key": api_key}, timeout=timeout)
    resp.raise_for_status()
    body = resp.json()
    if body.get("query_status") != "ok":
        return {"known": False, "status": body.get("query_status")}
    d = body["data"][0]
    return {"known": True, "signature": d.get("signature"), "tags": d.get("tags"), "file_type": d.get("file_type"),
            "first_seen": d.get("first_seen")}


def virustotal(sha256: str, api_key: str, timeout: float = 15) -> dict[str, Any]:
    resp = requests.get(f"https://www.virustotal.com/api/v3/files/{sha256}", headers={"x-apikey": api_key},
                        timeout=timeout)
    if resp.status_code == 404:
        return {"known": False}
    resp.raise_for_status()
    attrs = resp.json()["data"]["attributes"]
    stats = attrs.get("last_analysis_stats", {})
    return {"known": True, "malicious": stats.get("malicious"), "undetected": stats.get("undetected"),
            "label": (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label"),
            "type": attrs.get("type_description")}


def hash_reputation(sha256: str, cache=None) -> dict[str, Any]:
    from triage.enrich import IntelCache

    cache = cache or IntelCache()
    sources = {"malwarebazaar": (os.getenv("MALWAREBAZAAR_API_KEY"), malwarebazaar),
               "virustotal": (os.getenv("VT_API_KEY"), virustotal)}
    out: dict[str, Any] = {}
    for name, (key, fn) in sources.items():
        if not key:
            continue
        cached = cache.get(f"{name}:{sha256}")
        if cached is not None:
            out[name] = cached
            continue
        try:
            out[name] = fn(sha256, key)
            cache.put(f"{name}:{sha256}", out[name])
        except (requests.RequestException, KeyError, ValueError, IndexError) as exc:
            log.warning("%s lookup for %s failed: %s", name, sha256[:12], exc)
            out[name] = {"error": str(exc)[:200]}
    return out


def has_reputation_keys() -> bool:
    return bool(os.getenv("MALWAREBAZAAR_API_KEY") or os.getenv("VT_API_KEY"))


def main(argv: list[str] | None = None) -> int:
    from dotenv import load_dotenv

    load_dotenv()
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("paths", nargs="+", help="payload files or a downloads directory")
    parser.add_argument("--lookup", action="store_true", help="add MalwareBazaar / VirusTotal reputation")
    args = parser.parse_args(argv)
    files: list[Path] = []
    for p in map(Path, args.paths):
        # In a directory, skip Cowrie's own dotfiles (.gitignore); payloads are named by their hash.
        files.extend(sorted(f for f in p.iterdir() if f.is_file() and not f.name.startswith("."))
                     if p.is_dir() else [p])
    for f in files:
        info = analyze_file(f)
        if args.lookup:
            info["reputation"] = hash_reputation(info["sha256"])
        print(json.dumps({"file": str(f), **info}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
