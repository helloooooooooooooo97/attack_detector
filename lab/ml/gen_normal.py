#!/usr/bin/env python3
"""Diverse normal-traffic pcap generator for the ML dataset.

Produces several pcaps with realistic benign patterns, deliberately including
beacon-like but benign flows (chat polling, IoT telemetry, SSH keepalive) so
the classifier cannot cheat on "periodicity == malicious".

Patterns:
  browse    HTTPS browsing: short flows, human gaps, varied response sizes
  api       HTTPS API JSON POSTs: varied intervals 0.5-30s
  stream    video streaming: long connection, steady 1-8KB chunks
  download  big file downloads: one-shot large responses
  chat      messenger polling: GET every 8-15s (beacon-like, benign)
  iot       device telemetry: small POST every 20-30s (beacon-like, benign)
  ssh       SSH: long connection + keepalives 15-60s + interactive bursts
  dns       UDP query/response pairs with random gaps

Usage: python3 ml/gen_normal.py [flows_per_pattern] [out_dir]
"""

import os
import random
import struct
import sys

random.seed(20260812)


def ip_checksum(hdr):
    if len(hdr) % 2:
        hdr += b"\0"
    s = sum(struct.unpack("!%dH" % (len(hdr) // 2), hdr))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def eth(payload):
    return bytes.fromhex("02aabbcc0002") + bytes.fromhex("02aabbcc0001") + struct.pack("!H", 0x0800) + payload


def ipv4(src, dst, proto, payload):
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0,
                      bytes(map(int, src.split("."))), bytes(map(int, dst.split("."))))
    csum = ip_checksum(hdr)
    return hdr[:10] + struct.pack("!H", csum) + hdr[12:] + payload


def tcp(sport, dport, seq, ack, flags, payload=b""):
    return struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload


def udp(sport, dport, payload):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def tls_rec(typ, payload):
    return bytes([typ, 0x03, 0x03]) + struct.pack("!H", len(payload)) + payload


def client_hello(sni, tls13=True):
    body = (b"\x03\x03" if tls13 else b"\x03\x01") + bytes(random.getrandbits(8) for _ in range(32))
    body += b"\x20" + bytes(32)
    body += struct.pack("!H", 6) + (b"\x13\x01\x13\x02\x13\x03" if tls13 else b"\xc0\x2f\xc0\x2b\x00\x9c")
    body += b"\x01\x00"
    ext = b""
    if sni:
        name = b"\x00" + struct.pack("!H", len(sni)) + sni
        ext += struct.pack("!HH", 0, 2 + len(name)) + struct.pack("!H", len(name)) + name
    ext += struct.pack("!HH", 16, 5) + b"\x02h2"
    ext += struct.pack("!HH", 11, 4) + b"\x00\x02\x00\x00"
    pad = random.randint(0, 200)
    ext += struct.pack("!HH", 21, pad) + bytes(pad)
    body += struct.pack("!H", len(ext)) + ext
    return b"\x01" + struct.pack("!I", len(body))[1:] + body


SNIS = [b"www.example.com", b"api.github.com", b"cdn.cloudflare.com",
        b"mail.google.com", b"drive.google.com", b"login.microsoftonline.com",
        b"oss.aliyuncs.com", b"weixin.qq.com", b"www.baidu.com"]


class Pcap:
    def __init__(self, path):
        self.f = open(path, "wb")
        self.f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        self.t = 1_720_000_000.0

    def pkt(self, frame, dt=0.0002):
        self.t += dt
        s, u = int(self.t), int((self.t - int(self.t)) * 1e6)
        self.f.write(struct.pack("<IIII", s, u, len(frame), len(frame)))
        self.f.write(frame)

    def close(self):
        self.f.close()


def flow_pair(i):
    return (f"192.168.{i % 10}.{(i // 10) % 250 + 2}", f"203.0.113.{i % 240 + 1}")


def tls_pair(w, src, dst, sport, dport, seq, sni, resp_chunks):
    mac = "02aabbcc0002"
    w.pkt(eth(ipv4(src, dst, 6, tcp(sport, dport, seq, 0, 0x02))))
    w.pkt(eth(ipv4(dst, src, 6, tcp(dport, sport, 1, seq + 1, 0x12))))
    w.pkt(eth(ipv4(src, dst, 6, tcp(sport, dport, seq + 1, 1, 0x10))))
    w.pkt(eth(ipv4(src, dst, 6, tcp(sport, dport, seq + 2, 1, 0x18,
                   tls_rec(22, client_hello(sni))))), 0.001)
    w.pkt(eth(ipv4(dst, src, 6, tcp(dport, sport, 2, seq + 2 + 500, 0x18,
                   tls_rec(22, b"\x02" + bytes(random.randint(2200, 2600)))))), 0.001)
    for i, c in enumerate(resp_chunks):
        w.pkt(eth(ipv4(dst, src, 6, tcp(dport, sport, 3 + i, seq + 3 + i, 0x18, tls_rec(23, bytes(c))))), 0.001)
    w.pkt(eth(ipv4(src, dst, 6, tcp(sport, dport, seq + 4, 1, 0x11))), 0.001)


def http_pair(w, src, dst, sport, dport, seq, req, resp):
    w.pkt(eth(ipv4(src, dst, 6, tcp(sport, dport, seq, 0, 0x02))))
    w.pkt(eth(ipv4(dst, src, 6, tcp(dport, sport, 1, seq + 1, 0x12))))
    w.pkt(eth(ipv4(src, dst, 6, tcp(sport, dport, seq + 1, 1, 0x10))))
    w.pkt(eth(ipv4(src, dst, 6, tcp(sport, dport, seq + 2, 1, 0x18, req))), 0.001)
    w.pkt(eth(ipv4(dst, src, 6, tcp(dport, sport, 2, seq + 2 + len(req), 0x18, resp))), 0.001)
    w.pkt(eth(ipv4(src, dst, 6, tcp(sport, dport, seq + 3, 1, 0x11))), 0.001)


def gen_browse(w, i):
    src, dst = flow_pair(i)
    sni = random.choice(SNIS)
    tls_pair(w, src, dst, 40000 + i, 443, i * 1000, sni,
             [random.randint(300, 500), random.randint(1000, 30000)])
    for _ in range(random.randint(0, 3)):
        w.pkt(eth(ipv4(src, dst, 6, tcp(40000 + i, 443, i * 1000 + 5, 1, 0x18,
                   tls_rec(23, bytes(random.randint(100, 900)))))), random.uniform(0.1, 2.0))
        w.pkt(eth(ipv4(dst, src, 6, tcp(443, 40000 + i, 4, i * 1000 + 6, 0x18,
                   tls_rec(23, bytes(random.randint(500, 20000)))))), 0.001)


def gen_api(w, i):
    src, dst = flow_pair(i + 1000)
    sni = random.choice(SNIS)
    tls_pair(w, src, dst, 42000 + i, 443, i * 2000, sni,
             [random.randint(100, 800)])


def gen_stream(w, i):
    src, dst = flow_pair(i + 2000)
    sni = random.choice(SNIS)
    sport, dport, seq = 44000 + i, 443, i * 3000
    w.pkt(eth(ipv4(src, dst, 6, tcp(sport, dport, seq, 0, 0x02))))
    w.pkt(eth(ipv4(dst, src, 6, tcp(dport, sport, 1, seq + 1, 0x12))))
    w.pkt(eth(ipv4(src, dst, 6, tcp(sport, dport, seq + 1, 1, 0x10))))
    w.pkt(eth(ipv4(src, dst, 6, tcp(sport, dport, seq + 2, 1, 0x18,
                   tls_rec(22, client_hello(sni))))), 0.001)
    w.pkt(eth(ipv4(dst, src, 6, tcp(dport, sport, 2, seq + 2 + 500, 0x18,
                   tls_rec(22, b"\x02" + bytes(2400))))), 0.001)
    n = random.randint(30, 60)
    for k in range(n):
        chunk = random.randint(1000, 8000)
        w.pkt(eth(ipv4(dst, src, 6, tcp(dport, sport, 3 + k, seq + 3 + k, 0x18,
                   tls_rec(23, bytes(chunk))))), random.uniform(0.05, 0.5))


def gen_download(w, i):
    src, dst = flow_pair(i + 3000)
    sni = random.choice(SNIS)
    sport, dport, seq = 46000 + i, 443, i * 4000
    w.pkt(eth(ipv4(src, dst, 6, tcp(sport, dport, seq, 0, 0x02))))
    w.pkt(eth(ipv4(dst, src, 6, tcp(dport, sport, 1, seq + 1, 0x12))))
    w.pkt(eth(ipv4(src, dst, 6, tcp(sport, dport, seq + 1, 1, 0x10))))
    w.pkt(eth(ipv4(src, dst, 6, tcp(sport, dport, seq + 2, 1, 0x18,
                   tls_rec(22, client_hello(sni))))), 0.001)
    w.pkt(eth(ipv4(dst, src, 6, tcp(dport, sport, 2, seq + 2 + 500, 0x18,
                   tls_rec(22, b"\x02" + bytes(2400))))), 0.001)
    for k in range(random.randint(20, 60)):
        w.pkt(eth(ipv4(dst, src, 6, tcp(dport, sport, 3 + k, seq + 3 + k, 0x18,
                   tls_rec(23, bytes(1448))))), 0.0002)


def gen_chat(w, i):
    """messenger polling: benign but beacon-like (8-15s GET)."""
    src, dst = flow_pair(i + 4000)
    sni = random.choice(SNIS)
    sport, dport, seq = 48000 + i, 443, i * 5000
    for p in range(random.randint(3, 6)):
        w.pkt(eth(ipv4(src, dst, 6, tcp(sport, dport, seq, 0, 0x02))))
        w.pkt(eth(ipv4(dst, src, 6, tcp(dport, sport, 1, seq + 1, 0x12))))
        w.pkt(eth(ipv4(src, dst, 6, tcp(sport, dport, seq + 1, 1, 0x10))))
        w.pkt(eth(ipv4(src, dst, 6, tcp(sport, dport, seq + 2, 1, 0x18,
                       tls_rec(22, client_hello(sni))))), 0.001)
        w.pkt(eth(ipv4(dst, src, 6, tcp(dport, sport, 2, seq + 2 + 500, 0x18,
                       tls_rec(22, b"\x02" + bytes(2400))))), 0.001)
        w.pkt(eth(ipv4(src, dst, 6, tcp(sport, dport, seq + 3, 1, 0x18,
                       tls_rec(23, bytes(random.randint(120, 400)))))), 0.001)
        w.pkt(eth(ipv4(dst, src, 6, tcp(dport, sport, 3, seq + 3, 0x18,
                       tls_rec(23, bytes(random.randint(300, 900)))))), 0.001)
        w.pkt(eth(ipv4(src, dst, 6, tcp(sport, dport, seq + 4, 1, 0x11))), 0.001)
        seq += 100
        w.pkt(eth(ipv4(src, dst, 6, tcp(sport, dport, seq, 1, 0x02))), random.uniform(8, 15))
        seq += 100


def gen_iot(w, i):
    """device telemetry: benign but beacon-like (20-30s small POST)."""
    src, dst = flow_pair(i + 5000)
    sport, dport, seq = 50000 + i, 8080, i * 6000
    for p in range(random.randint(3, 5)):
        req = b"POST /telemetry HTTP/1.1\r\nHost: iot.local\r\nContent-Length: 80\r\n\r\n" + bytes(80)
        resp = b"HTTP/1.1 200 OK\r\nContent-Length: 40\r\n\r\n" + bytes(40)
        http_pair(w, src, dst, sport, dport, seq, req, resp)
        seq += 100
        w.pkt(eth(ipv4(src, dst, 6, tcp(sport, dport, seq, 1, 0x02))), random.uniform(20, 30))
        seq += 100


def gen_ssh(w, i):
    src, dst = flow_pair(i + 6000)
    sport, dport, seq = 52000 + i, 22, i * 7000
    w.pkt(eth(ipv4(src, dst, 6, tcp(sport, dport, seq, 0, 0x02))))
    w.pkt(eth(ipv4(dst, src, 6, tcp(dport, sport, 1, seq + 1, 0x12))))
    w.pkt(eth(ipv4(src, dst, 6, tcp(sport, dport, seq + 1, 1, 0x10))))
    w.pkt(eth(ipv4(src, dst, 6, tcp(sport, dport, seq + 2, 1, 0x18, bytes(random.randint(200, 400))))), 0.01)
    w.pkt(eth(ipv4(dst, src, 6, tcp(dport, sport, 2, seq + 3, 0x18, bytes(random.randint(200, 600))))), 0.01)
    for k in range(random.randint(4, 8)):
        w.pkt(eth(ipv4(src, dst, 6, tcp(sport, dport, seq + 3 + k, 1, 0x18, bytes(random.randint(20, 80))))),
              random.uniform(15, 60))
        w.pkt(eth(ipv4(dst, src, 6, tcp(dport, sport, 3 + k, seq + 4 + k, 0x18, bytes(random.randint(20, 80))))), 0.01)
    w.pkt(eth(ipv4(src, dst, 6, tcp(sport, dport, seq + 12, 1, 0x11))), 0.01)


def gen_dns(w, i):
    src, dst = flow_pair(i + 7000)
    for _ in range(random.randint(3, 6)):
        q = bytes(random.getrandbits(8) for _ in range(random.randint(40, 80)))
        r = bytes(random.getrandbits(8) for _ in range(random.randint(80, 200)))
        w.pkt(eth(ipv4(src, dst, 17, udp(53000 + i, 53, q))), random.uniform(0.01, 5))
        w.pkt(eth(ipv4(dst, src, 17, udp(53, 53000 + i, r))), 0.01)


# ---------------------------------------------------------------------------
# "legitimate but probe-like" single-source patterns: one machine doing many
# short connections -- the hard negative cases for brute-force detection.
# ---------------------------------------------------------------------------

def gen_healthcheck(w, i):
    """Monitoring server (Zabbix/Nagios style) checking hosts on :80."""
    src = "10.9.9.50"
    for cyc in range(4):
        for j in range(8):
            dst = f"10.9.10.{j + 1}"
            sport = 30000 + i * 40 + cyc * 8 + j
            seq = i * 5000 + cyc * 100 + j * 10
            req = b"GET /health HTTP/1.1\r\nHost: app\r\n\r\n"
            resp = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nOK"
            http_pair(w, src, dst, sport, 80, seq, req, resp)
            w.t += random.uniform(0.5, 2.0)
        w.t += random.uniform(20, 40)  # next check cycle


def gen_flaky_ssh(w, i):
    """A client with unstable network: a handful of reconnects with backoff
    (realistic flakiness, ~8 attempts over ~4 minutes)."""
    src, dst = "10.9.9.10", "10.9.9.20"
    for k in range(8):
        sport = 22000 + i * 40 + k
        seq = i * 7000 + k * 100
        w.pkt(eth(ipv4(src, dst, 6, tcp(sport, 22, seq, 0, 0x02))))
        w.pkt(eth(ipv4(dst, src, 6, tcp(22, sport, 1, seq + 1, 0x12))))
        w.pkt(eth(ipv4(src, dst, 6, tcp(sport, 22, seq + 1, 1, 0x10))))
        w.pkt(eth(ipv4(src, dst, 6, tcp(sport, 22, seq + 2, 1, 0x18,
                       b"SSH-2.0-OpenSSH_8.9\r\n"))), 0.01)
        w.pkt(eth(ipv4(dst, src, 6, tcp(22, sport, 2, seq + 3, 0x18,
                       b"SSH-2.0-OpenSSH_8.9p1\r\n"))), 0.01)
        w.pkt(eth(ipv4(src, dst, 6, tcp(sport, 22, seq + 3, 1, 0x11))), 0.01)
        w.t += random.uniform(20, 50)  # reconnect with backoff (20-50s)


def gen_crawler(w, i):
    """A web crawler fetching many pages from one host."""
    src, dst = "10.9.9.11", "10.9.9.30"
    for k in range(40):
        sport = 23000 + i * 50 + k
        seq = i * 8000 + k * 50
        req = b"GET /page HTTP/1.1\r\nHost: www.site.local\r\nUser-Agent: Bot/1.0\r\n\r\n"
        resp = b"HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n" + bytes(500)
        http_pair(w, src, dst, sport, 80, seq, req, resp)
        w.t += random.uniform(0.15, 0.5)


def gen_browser_burst(w, i):
    """A browser loading a page with many resources over short TLS conns."""
    src, dst = "10.9.9.12", "10.9.9.40"
    sni = random.choice(SNIS)
    for k in range(30):
        sport = 24000 + i * 40 + k
        seq = i * 9000 + k * 60
        tls_pair(w, src, dst, sport, 443, seq, sni,
                 [random.randint(300, 900), random.randint(1000, 5000)])
        w.t += random.uniform(0.05, 0.35)


def gen_dns_storm(w, i):
    """A resolver client issuing many queries (cache warmup / NXDOMAIN storm)."""
    src = "10.9.9.13"
    for k in range(50):
        q = bytes(random.getrandbits(8) for _ in range(random.randint(40, 80)))
        r = bytes(random.getrandbits(8) for _ in range(random.randint(60, 180)))
        sport = 25000 + i * 60 + k
        w.pkt(eth(ipv4(src, "10.9.9.53", 17, udp(sport, 53, q))), random.uniform(0.02, 0.2))
        w.pkt(eth(ipv4("10.9.9.53", src, 17, udp(53, sport, r))), 0.01)


PATTERNS = {
    "browse": gen_browse, "api": gen_api, "stream": gen_stream,
    "download": gen_download, "chat": gen_chat, "iot": gen_iot,
    "ssh": gen_ssh, "dns": gen_dns,
}

PROBE_LIKE = {
    "healthcheck": (gen_healthcheck, 20),
    "flaky_ssh": (gen_flaky_ssh, 20),
    "crawler": (gen_crawler, 20),
    "browser_burst": (gen_browser_burst, 20),
    "dns_storm": (gen_dns_storm, 20),
}


def main():
    per = int(sys.argv[1]) if len(sys.argv) > 1 else 150
    outdir = sys.argv[2] if len(sys.argv) > 2 else os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "out")
    total = 0
    for name, fn in PATTERNS.items():
        path = os.path.join(outdir, f"normal_{name}.pcap")
        w = Pcap(path)
        i = 0
        for k in range(per):
            fn(w, i)
            i += 1
        w.close()
        total += per
        print(f"normal_{name}.pcap: {per} flows")
    for name, (fn, episodes) in PROBE_LIKE.items():
        path = os.path.join(outdir, f"normal_{name}.pcap")
        w = Pcap(path)
        for k in range(episodes):
            fn(w, k)
        w.close()
        total += episodes
        print(f"normal_{name}.pcap: {episodes} episodes")
    print(f"generated {total} normal flows -> {outdir}")


if __name__ == "__main__":
    main()
