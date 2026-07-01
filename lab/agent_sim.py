#!/usr/bin/env python3
"""Wazuh agent keepalive simulator (DB-only lab).

Speaks the Wazuh secure-message protocol (AES-256-CBC) well enough to send a
startup + periodic keepalives so a *registered* agent shows **Active** in the
manager/dashboard -- without any real endpoint. Uses only stdlib + the openssl
CLI for AES.

Protocol (reversed from wazuh v4.14 src/os_crypto):
  AES key   = ascii( md5_hex(raw_key) )            # 32 bytes -> AES-256
  IV        = "FEDCBA0987654321"                   # fixed, 16 bytes
  plaintext = ('!' * bfsize) + zlib( md5_hex(H+body) + H + body )
              H = "%05hu%010u:%04u:" (rand, global_count, local_count)
              bfsize = 8 - (len(zlib) % 8)
  wire      = "!<id>!#AES:" + AES256CBC(plaintext, key, IV)   # PKCS#7
  TCP frame = struct.pack("<I", len(wire)) + wire
"""
import argparse
import hashlib
import os
import random
import socket
import struct
import subprocess
import sys
import threading
import time
import zlib

IV = b"FEDCBA0987654321"


def aes_key_hex(raw_key: str) -> str:
    """32-byte AES-256 key = ascii(md5_hex(raw_key)); return as 64 hex chars."""
    return hashlib.md5(raw_key.encode()).hexdigest().encode().hex()


def aes_encrypt(plain: bytes, key_hex: str) -> bytes:
    p = subprocess.run(
        ["openssl", "enc", "-aes-256-cbc", "-K", key_hex, "-iv", IV.hex()],
        input=plain, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
    )
    return p.stdout


def build_frame(agent_id: str, key_hex: str, body: str,
                gcount: int, lcount: int) -> bytes:
    rand1 = random.randint(0, 65535)
    header = "%05hu%010u:%04u:" % (rand1, gcount, lcount)
    tmp = (header + body).encode("latin-1", "replace")
    md5 = hashlib.md5(tmp).hexdigest().encode()          # 32 bytes
    fin = md5 + tmp
    comp = zlib.compress(fin)
    bfsize = 8 - (len(comp) % 8)                          # 1..8
    plain = (b"!" * bfsize) + comp
    cipher = aes_encrypt(plain, key_hex)
    wire = b"!" + agent_id.encode() + b"!#AES:" + cipher
    return struct.pack("<I", len(wire)) + wire


# Per-OS agent-info strings. remoted/wazuh-db parses the bracketed
# [os_name|os_platform:codename|os_version] to set the agent OS shown in the
# dashboard. os_platform "windows" gives the agent a Windows identity/icon.
OS_TEMPLATES = {
    "linux":
        "#!-Linux |%s |5.15.0-lab |#1 SMP lab |x86_64 "
        "[Ubuntu|ubuntu:|22.04.4 LTS] - Wazuh v4.14.5 / lab-sim",
    "windows-server":
        "#!-Microsoft Windows Server 2019 Datacenter |%s |10.0.17763.107 "
        "|(WinNT) |x86_64 [Microsoft Windows Server 2019 Datacenter|windows:|"
        "10.0.17763.107] - Wazuh v4.14.5 / lab-sim",
    "windows-10":
        "#!-Microsoft Windows 10 Pro |%s |10.0.19045.4291 |(WinNT) |x86_64 "
        "[Microsoft Windows 10 Pro|windows:|10.0.19045.4291] - Wazuh v4.14.5 / lab-sim",
    "windows-11":
        "#!-Microsoft Windows 11 Enterprise |%s |10.0.22631.3593 |(WinNT) |x86_64 "
        "[Microsoft Windows 11 Enterprise|windows:|10.0.22631.3593] - Wazuh v4.14.5 / lab-sim",
}


def keepalive_body(name: str, os_key: str = "linux") -> str:
    # A control message that is NOT "#!-agent startup/shutdown/ack" is treated
    # by remoted as a keepalive -> updates last_keepalive -> agent goes Active.
    tmpl = OS_TEMPLATES.get(os_key, OS_TEMPLATES["linux"])
    return (tmpl % name) + "\nlab000000000000000000000000000000 merged.mg\n"


def startup_body() -> str:
    return "#!-agent startup {\"version\":\"Wazuh v4.14.5\"}"


def run_agent(agent_id, name, raw_key, manager, port, interval, stop, os_key="linux"):
    key_hex = aes_key_hex(raw_key)
    gcount = int(time.time()) & 0xFFFFFFFF
    lcount = 0
    sock = None

    def connect():
        s = socket.create_connection((manager, port), timeout=10)
        return s

    def send(body):
        nonlocal lcount, sock
        lcount += 1
        frame = build_frame(agent_id, key_hex, body, gcount, lcount)
        sock.sendall(frame)

    try:
        sock = connect()
        send(startup_body())
        print("[%s/%s] startup sent" % (agent_id, name), flush=True)
        while not stop.is_set():
            try:
                send(keepalive_body(name, os_key))
                print("[%s/%s] keepalive g=%u l=%u" % (agent_id, name, gcount, lcount),
                      flush=True)
            except (BrokenPipeError, ConnectionResetError, OSError) as e:
                print("[%s/%s] reconnect (%s)" % (agent_id, name, e), flush=True)
                try:
                    sock.close()
                except OSError:
                    pass
                sock = connect()
                gcount = int(time.time()) & 0xFFFFFFFF
                lcount = 0
                send(startup_body())
            stop.wait(interval)
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass


def parse_keys(path):
    out = []
    with open(path) as fh:
        for line in fh:
            parts = line.split()
            if len(parts) >= 4 and not parts[0].startswith("#"):
                out.append((parts[0], parts[1], parts[3]))  # id, name, key
    return out


def load_osmap(path):
    """name -> os_key map (lines: '<name> <os_key>'). Missing -> linux."""
    m = {}
    try:
        with open(path) as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 2 and not parts[0].startswith("#"):
                    m[parts[0]] = parts[1]
    except OSError:
        pass
    return m


def main():
    ap = argparse.ArgumentParser(description="Wazuh agent keepalive simulator")
    ap.add_argument("--manager", default=os.environ.get("MANAGER_IP", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("MANAGER_PORT", "1514")))
    ap.add_argument("--interval", type=int, default=int(os.environ.get("KEEPALIVE_INTERVAL", "30")))
    ap.add_argument("--keys", help="path to a client.keys file")
    ap.add_argument("--osmap", default=os.environ.get("OSMAP_FILE"),
                    help="path to a 'name os_key' map (windows-server/-10/-11/linux)")
    ap.add_argument("--agent", action="append", default=[],
                    help="id:name:rawkey (repeatable)")
    args = ap.parse_args()

    agents = []
    if args.keys:
        agents += parse_keys(args.keys)
    for a in args.agent:
        i, n, k = a.split(":", 2)
        agents.append((i, n, k))
    if not agents:
        ap.error("no agents (use --keys or --agent id:name:rawkey)")

    osmap = load_osmap(args.osmap) if args.osmap else {}

    print("simulating %d agent(s) -> %s:%d every %ds"
          % (len(agents), args.manager, args.port, args.interval), flush=True)
    stop = threading.Event()
    threads = []
    for i, n, k in agents:
        os_key = osmap.get(n, "linux")
        t = threading.Thread(target=run_agent,
                             args=(i, n, k, args.manager, args.port, args.interval, stop, os_key),
                             daemon=True)
        t.start()
        threads.append(t)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop.set()
        print("\nstopping", flush=True)


if __name__ == "__main__":
    main()
