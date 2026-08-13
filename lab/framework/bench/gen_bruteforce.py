#!/usr/bin/env python3
"""Generate brute-force / port-scan traffic pcaps for detection testing.

Patterns:
  bf_ssh    : SSH brute force  - many short TCP sessions to :22, small
              banner/auth payloads, rapid succession
  bf_http   : HTTP login brute force - many short POST /login to :8080
  scan_syn  : TCP SYN sweep - one SYN to many different ports (no payload)

Usage: python3 framework/bench/gen_bruteforce.py [out_dir]
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


class Pcap:
    def __init__(self, path):
        self.f = open(path, "wb")
        self.f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        self.t = 1_720_000_000.0

    def pkt(self, frame, dt=0.001):
        self.t += dt
        s, u = int(self.t), int((self.t - int(self.t)) * 1e6)
        self.f.write(struct.pack("<IIII", s, u, len(frame), len(frame)))
        self.f.write(frame)

    def close(self):
        self.f.close()


def ssh_attempt(w, src, dst, i):
    """One SSH connection attempt: banner exchange + auth failure, then close."""
    sport, dport, seq = 20000 + (i % 60000), 22, i * 1000
    mac = "02aabbcc0002"
    w.pkt(eth(ipv4(src, dst, 6, tcp(sport, dport, seq, 0, 0x02))))
    w.pkt(eth(ipv4(dst, src, 6, tcp(dport, sport, 1, seq + 1, 0x12))))
    w.pkt(eth(ipv4(src, dst, 6, tcp(sport, dport, seq + 1, 1, 0x10))))
    w.pkt(eth(ipv4(src, dst, 6, tcp(sport, dport, seq + 2, 1, 0x18,
                   b"SSH-2.0-OpenSSH_8.9\r\n"))), 0.005)
    w.pkt(eth(ipv4(dst, src, 6, tcp(dport, sport, 2, seq + 3, 0x18,
                   b"SSH-2.0-OpenSSH_8.9p1 Ubuntu\r\n"))), 0.005)
    w.pkt(eth(ipv4(src, dst, 6, tcp(sport, dport, seq + 3, 1, 0x18, bytes(48)))), 0.005)
    w.pkt(eth(ipv4(dst, src, 6, tcp(dport, sport, 3, seq + 4, 0x18, bytes(32)))), 0.005)
    w.pkt(eth(ipv4(src, dst, 6, tcp(sport, dport, seq + 4, 1, 0x11))), 0.005)


def http_login(w, src, dst, i):
    """One HTTP login POST attempt."""
    sport, dport, seq = 30000 + (i % 60000), 8080, i * 2000
    req = (b"POST /login HTTP/1.1\r\nHost: app.local\r\nContent-Type: "
           b"application/x-www-form-urlencoded\r\nContent-Length: 60\r\n\r\n"
           b"user=admin&pass=" + bytes(36))
    w.pkt(eth(ipv4(src, dst, 6, tcp(sport, dport, seq, 0, 0x02))))
    w.pkt(eth(ipv4(dst, src, 6, tcp(dport, sport, 1, seq + 1, 0x12))))
    w.pkt(eth(ipv4(src, dst, 6, tcp(sport, dport, seq + 1, 1, 0x10))))
    w.pkt(eth(ipv4(src, dst, 6, tcp(sport, dport, seq + 2, 1, 0x18, req))), 0.005)
    w.pkt(eth(ipv4(dst, src, 6, tcp(dport, sport, 2, seq + 2 + len(req), 0x18,
                   b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 20\r\n\r\n"))), 0.005)
    w.pkt(eth(ipv4(src, dst, 6, tcp(sport, dport, seq + 3, 1, 0x11))), 0.005)


def syn_scan(w, src, dst, i):
    """One SYN to a distinct port (no response)."""
    sport, dport, seq = 40000 + (i % 60000), 1024 + (i % 60000), i * 3000
    w.pkt(eth(ipv4(src, dst, 6, tcp(sport, dport, seq, 0, 0x02))), 0.001)


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "out")
    src, dst = "10.0.0.7", "10.0.0.9"
    gen = [("bf_ssh", ssh_attempt, 900, 0.012),
           ("bf_http", http_login, 900, 0.012),
           ("scan_syn", syn_scan, 3000, 0.004)]
    for name, fn, n, gap in gen:
        w = Pcap(os.path.join(outdir, f"{name}.pcap"))
        for i in range(n):
            fn(w, src, dst, i)
            w.t += gap  # ~80/s for bf, ~250/s for scan
        w.close()
        print(f"{name}.pcap: {n} attempts")


if __name__ == "__main__":
    main()
