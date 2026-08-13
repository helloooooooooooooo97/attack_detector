#!/usr/bin/env python3
"""Generic beacon/RAT protocol driver for TFLab.

Runs a tool-specific profile against a local lab C2 endpoint and produces
traffic faithful to the tool's documented encrypted-traffic fingerprint:
transport (http/https/tcp), URI, form params, payload sizing, checkin
interval + jitter, UA/SNI, frame magic for raw TCP tools.

Usage:
  beacon_agent.py --profile profiles/<tool>.json [--host 127.0.0.1]

Each profile is a JSON file; see profiles/nimplant.json for the schema.
The server side is beacon_server.py (started by the scenario run.sh).
"""

import argparse
import base64
import hashlib
import http.client
import json
import os
import random
import socket
import ssl
import sys
import time
import urllib.parse
import urllib.request


_conns = {}


def http_conn(profile, host):
    """Reusable HTTP(S) connection for keep-alive (long-lived channel)."""
    key = (profile["transport"], host, profile["port"])
    c = _conns.get(key)
    if c is None:
        if profile["transport"] == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            c = http.client.HTTPSConnection(host, profile["port"], context=ctx, timeout=10)
        else:
            c = http.client.HTTPConnection(host, profile["port"], timeout=10)
        _conns[key] = c
    return c


def payload_bytes(seed, size):
    """Deterministic pseudo-random bytes of exactly `size` (reproducible)."""
    out = b""
    i = 0
    while len(out) < size:
        out += hashlib.sha256(f"{seed}:{i}".encode()).digest()
        i += 1
    return out[:size]


def encode(value, style):
    if style == "b64":
        return base64.b64encode(value).decode()
    if style == "hex":
        return value.hex()
    if style == "none":
        try:
            return value.decode("latin1")
        except UnicodeDecodeError:
            return value.decode("latin1", "replace")
    return value.decode("latin1", "replace")


def build_body(profile, cycle):
    rmin, rmax = profile.get("req_size", [300, 600])
    size = random.randint(rmin, rmax)
    raw = payload_bytes(f"{profile['name']}:{cycle}", size)
    params = profile.get("params") or [["data", "b64"]]
    fields = []
    for i, (name, style) in enumerate(params):
        if i == len(params) - 1:
            fields.append((name, encode(raw, style)))
        else:
            fields.append((name, encode(payload_bytes(f"{name}:{cycle}", 32), style)))
    return urllib.parse.urlencode(fields).encode()


def http_checkin(profile, cycle, host):
    port = profile["port"]
    scheme = "https" if profile["transport"] == "https" else "http"
    method = profile.get("method", "POST")
    headers = {
        "User-Agent": profile.get("headers", {}).get("User-Agent", "Mozilla/5.0"),
        "Connection": "close" if not profile.get("keep_alive") else "keep-alive",
    }
    for k, v in (profile.get("headers") or {}).items():
        if k != "User-Agent":
            headers[k] = v
    if method == "GET":
        qs = urllib.parse.urlencode([
            (n, encode(payload_bytes(f"{n}:{cycle}", 24), st))
            for n, st in (profile.get("params") or [["doc", "b64"]])
        ])
        path = f"{profile.get('path', '/')}?{qs}"
        body = None
    else:
        path = profile.get("path", "/")
        body = build_body(profile, cycle)
    if profile.get("keep_alive"):
        conn = http_conn(profile, host)
        try:
            conn.request(method, path, body=body, headers=headers)
            resp = conn.getresponse()
            data = resp.read()
            return len(body or b""), len(data)
        except Exception:
            _conns.pop((profile["transport"], host, port), None)
            raise
    req = urllib.request.Request(
        f"{scheme}://{host}:{port}{path}", data=body, method=method, headers=headers)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, timeout=10, context=ctx) as r:
        resp = r.read()
    return len(body or b""), len(resp)


def tcp_checkin(profile, cycle, host):
    port = profile["port"]
    frame = profile.get("frame", {})
    hlen = frame.get("header_len", 8)
    magic = bytes.fromhex(frame.get("magic", "00000000"))
    rmin, rmax = profile.get("req_size", [300, 600])
    raw = payload_bytes(f"{profile['name']}:{cycle}", random.randint(rmin, rmax))
    header = magic + len(raw).to_bytes(hlen - len(magic), "big")
    with socket.create_connection((host, port), timeout=10) as s:
        s.sendall(header + raw)
        resp = s.recv(65535)
    return len(header) + len(raw), len(resp)


def tcp_stream_run(profile, host):
    """One long-lived TCP connection with periodic framed records."""
    port = profile["port"]
    frame = profile.get("frame", {})
    hlen = frame.get("header_len", 8)
    magic = bytes.fromhex(frame.get("magic", "00000000"))
    interval = profile.get("interval", 10.0)
    jitter = profile.get("jitter", 0.1)
    duration = profile.get("duration", 60)
    rmin, rmax = profile.get("req_size", [100, 300])
    with socket.create_connection((host, port), timeout=10) as s:
        start = time.time()
        cycle = 0
        while time.time() - start < duration:
            raw = payload_bytes(f"{profile['name']}:{cycle}", random.randint(rmin, rmax))
            s.sendall(magic + len(raw).to_bytes(hlen - len(magic), "big") + raw)
            try:
                resp = s.recv(65535)
            except socket.timeout:
                resp = b""
            print(f"[ok] cycle={cycle} req={len(raw)+hlen}B resp={len(resp)}B", flush=True)
            cycle += 1
            time.sleep(interval * (1 + random.uniform(-jitter, jitter)))


def udp_run(profile, host):
    """UDP channel: periodic fixed-size datagrams (covert tunnel / backup C2)."""
    port = profile["port"]
    interval = profile.get("interval", 10.0)
    jitter = profile.get("jitter", 0.1)
    duration = profile.get("duration", 60)
    size = profile.get("req_size", [64, 64])[0]
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        start = time.time()
        cycle = 0
        while time.time() - start < duration:
            s.sendto(payload_bytes(f"{profile['name']}:{cycle}", size), (host, port))
            s.settimeout(2)
            try:
                resp, _ = s.recvfrom(65535)
            except socket.timeout:
                resp = b""
            print(f"[ok] cycle={cycle} req={size}B resp={len(resp)}B", flush=True)
            cycle += 1
            time.sleep(interval * (1 + random.uniform(-jitter, jitter)))


def burst_run(profile, host):
    """Stealer-style bursts: several rapid upload-heavy POSTs, then idle."""
    duration = profile.get("duration", 60)
    burst_n = profile.get("burst_n", 6)
    burst_gap = profile.get("burst_gap", 0.4)
    idle_gap = profile.get("idle_gap", 25.0)
    start = time.time()
    cycle = 0
    while time.time() - start < duration:
        for i in range(burst_n):
            try:
                req, resp = http_checkin(profile, cycle, host)
                print(f"[ok] burst-cycle={cycle} req={req}B resp={resp}B", flush=True)
            except Exception as e:  # noqa: BLE001
                print(f"[fail] burst-cycle={cycle}: {e}", file=sys.stderr, flush=True)
            cycle += 1
            time.sleep(burst_gap)
        time.sleep(idle_gap * (1 + random.uniform(-0.2, 0.2)))


def multiphase_run(profile, host):
    """Two-phase campaign: delivery burst(s) then persistent C2 channel."""
    duration = profile.get("duration", 90)
    phases = profile.get("phases", [])
    if not phases:
        raise SystemExit("multiphase profile needs phases[]")
    start = time.time()
    total = 0.0
    for ph in phases:
        ph_duration = min(ph.get("duration", 30), duration - total)
        sub = dict(profile)
        sub.update(ph)
        sub["duration"] = ph_duration
        sub["name"] = profile["name"] + "-" + ph.get("phase", "p")
        if ph.get("mode", "http") == "burst":
            burst_run(sub, host)
        elif sub.get("transport") in ("http", "https"):
            hstart = time.time()
            while time.time() - hstart < ph_duration:
                try:
                    req, resp = http_checkin(sub, int(total + (time.time() - hstart)),
                                             ph.get("host") or host)
                    print(f"[ok] {sub['name']} req={req}B resp={resp}B", flush=True)
                except Exception as e:  # noqa: BLE001
                    print(f"[fail] {sub['name']}: {e}", file=sys.stderr, flush=True)
                time.sleep(sub.get("interval", 10.0) * (1 + random.uniform(-0.1, 0.1)))
        else:
            tcp_stream_run(sub, host)
        total += ph_duration


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", required=True)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--cycles", type=int, default=0, help="0 = run until duration")
    args = ap.parse_args()

    profile = json.load(open(args.profile, encoding="utf-8"))
    duration = profile.get("duration", 60)
    interval = profile.get("interval", 10.0)
    jitter = profile.get("jitter", 0.1)
    # connect via the profile hostname so the TLS ClientHello carries the
    # tool-specific SNI (scenario run.sh maps it to 127.0.0.1 in /etc/hosts)
    host = profile.get("host") or args.host

    print(f"beacon[{profile['name']}] -> {profile['transport']}://{host}:{profile['port']} "
          f"{profile.get('path', 'tcp')} interval={interval}s±{jitter}", flush=True)
    start = time.time()
    cycle = 0
    while args.cycles == 0 or cycle < args.cycles:
        if time.time() - start >= duration:
            break
        mode = profile.get("mode", "http")
        if mode in ("tcp_stream", "udp", "burst", "multiphase"):
            if mode == "tcp_stream":
                tcp_stream_run(profile, host)
            elif mode == "udp":
                udp_run(profile, host)
            elif mode == "burst":
                burst_run(profile, host)
            else:
                multiphase_run(profile, host)
            break
        try:
            if profile["transport"] in ("http", "https"):
                req, resp = http_checkin(profile, cycle, host)
            else:
                req, resp = tcp_checkin(profile, cycle, host)
            print(f"[ok] cycle={cycle} req={req}B resp={resp}B", flush=True)
        except Exception as e:  # noqa: BLE001
            print(f"[fail] cycle={cycle}: {e}", file=sys.stderr, flush=True)
        cycle += 1
        sleep = interval * (1 + random.uniform(-jitter, jitter))
        time.sleep(max(0.2, sleep))


if __name__ == "__main__":
    main()
