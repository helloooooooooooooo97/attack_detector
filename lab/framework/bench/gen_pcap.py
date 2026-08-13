#!/usr/bin/env python3
"""Synthetic mixed-traffic pcap generator for probe load testing.

Produces a classic Ethernet pcap mixing tool-shaped flows:
  - behinder-like TLS flows (big 8225B request chunks, 13 records)
  - HTTPS beacon short flows (ClientHello + POST appdata)
  - plain HTTP short flows
  - UDP beacon datagrams
  - small background TCP pairs

Usage: python3 framework/bench/gen_pcap.py [total_packets] [out.pcap]
"""

import os
import random
import struct
import sys

random.seed(20260811)


def ip_checksum(hdr):
    if len(hdr) % 2:
        hdr += b"\0"
    s = sum(struct.unpack("!%dH" % (len(hdr) // 2), hdr))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def eth(src_mac, dst_mac, eth_type, payload):
    return bytes.fromhex(dst_mac.replace(":", "")) + bytes.fromhex(src_mac.replace(":", "")) + struct.pack("!H", eth_type) + payload


def ipv4(src, dst, proto, payload):
    ver_ihl = 0x45
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s", ver_ihl, 0, total, 1, 0, 64, proto, 0,
                      bytes(map(int, src.split("."))), bytes(map(int, dst.split("."))))
    csum = ip_checksum(hdr)
    hdr = hdr[:10] + struct.pack("!H", csum) + hdr[12:]
    return hdr + payload


def tcp(sport, dport, seq, ack, flags, payload=b""):
    off = 5
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, off << 4, flags, 65535, 0, 0)
    return hdr + payload


def tls_record(typ, payload):
    return bytes([typ, 0x03, 0x03]) + struct.pack("!H", len(payload)) + payload


def client_hello(sni=b""):
    body = b"\x03\x03" + bytes(random.getrandbits(8) for _ in range(32))
    body += b"\x20" + bytes(32)
    ciphers = struct.pack("!H", 6) + b"\x13\x01\x13\x02\x13\x03"
    body += ciphers + b"\x01\x00"
    ext = b""
    if sni:
        name = b"\x00" + struct.pack("!H", len(sni)) + sni
        ext += struct.pack("!HH", 0, 2 + len(name)) + struct.pack("!H", len(name)) + name
    alpn = struct.pack("!HH", 16, 5) + b"\x02h2"
    ext += alpn
    ext += struct.pack("!HH", 11, 4) + b"\x00\x02\x00\x00"
    body += struct.pack("!H", len(ext)) + ext
    return b"\x01" + struct.pack("!I", len(body))[1:] + body


class PcapWriter:
    def __init__(self, path):
        self.f = open(path, "wb")
        self.f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        self.ts = 1_700_000_000.0

    def pkt(self, frame, ts_delta=0.0001):
        self.ts += ts_delta
        sec, usec = int(self.ts), int((self.ts - int(self.ts)) * 1_000_000)
        self.f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
        self.f.write(frame)

    def close(self):
        self.f.close()


def flow_key(i):
    return (f"10.{(i % 200) + 1}.{(i // 200) % 250}.{(i // 50000) % 250 + 1}",
            f"10.200.{(i // 300) % 250}.{(i // 70000) % 250 + 1}")


def behinder_flow(w, i, port):
    src, dst = flow_key(i)
    sport = 40000 + (i % 20000)
    mac = "02:00:00:00:%02x:%02x" % ((i >> 8) & 0xFF, i & 0xFF)
    seq = i * 1000
    # handshake
    w.pkt(eth(mac, "02:00:00:00:00:01", 0x0800, ipv4(src, dst, 6, tcp(sport, port, seq, 0, 0x02))))
    w.pkt(eth("02:00:00:00:00:01", mac, 0x0800, ipv4(dst, src, 6, tcp(port, sport, 1, seq + 1, 0x12))))
    w.pkt(eth(mac, "02:00:00:00:00:01", 0x0800, ipv4(src, dst, 6, tcp(sport, port, seq + 1, 1, 0x10))))
    # TLS: ClientHello + ServerHello/cert + appdata chunks
    w.pkt(eth(mac, "02:00:00:00:00:01", 0x0800, ipv4(src, dst, 6, tcp(sport, port, seq + 2, 1, 0x18, tls_record(22, client_hello(b"behinder.local"))))))
    w.pkt(eth("02:00:00:00:00:01", mac, 0x0800, ipv4(dst, src, 6, tcp(port, sport, 2, seq + 2 + 519, 0x18, tls_record(22, b"\x02" + bytes(2400))))))
    # all request chunks first, then all responses -> a single exchange
    for k in range(4):
        app = bytes(random.getrandbits(8) for _ in range(8225))
        w.pkt(eth(mac, "02:00:00:00:00:01", 0x0800, ipv4(src, dst, 6, tcp(sport, port, seq + 3 + k, 1, 0x18, tls_record(23, app)))))
    for k in range(4):
        w.pkt(eth("02:00:00:00:00:01", mac, 0x0800, ipv4(dst, src, 6, tcp(port, sport, 3 + k, seq + 3 + k, 0x18, tls_record(23, bytes(400))))))
    w.pkt(eth(mac, "02:00:00:00:00:01", 0x0800, ipv4(src, dst, 6, tcp(sport, port, seq + 7, 1, 0x11))))


def https_beacon_flow(w, i, port, sni):
    src, dst = flow_key(i)
    sport = 30000 + (i % 20000)
    mac = "02:00:00:00:%02x:%02x" % ((i >> 8) & 0xFF, i & 0xFF)
    seq = i * 2000
    w.pkt(eth(mac, "02:00:00:00:00:01", 0x0800, ipv4(src, dst, 6, tcp(sport, port, seq, 0, 0x02))))
    w.pkt(eth("02:00:00:00:00:01", mac, 0x0800, ipv4(dst, src, 6, tcp(port, sport, 1, seq + 1, 0x12))))
    w.pkt(eth(mac, "02:00:00:00:00:01", 0x0800, ipv4(src, dst, 6, tcp(sport, port, seq + 1, 1, 0x10))))
    w.pkt(eth(mac, "02:00:00:00:00:01", 0x0800, ipv4(src, dst, 6, tcp(sport, port, seq + 2, 1, 0x18, tls_record(22, client_hello(sni))))))
    w.pkt(eth("02:00:00:00:00:01", mac, 0x0800, ipv4(dst, src, 6, tcp(port, sport, 2, seq + 2 + 520, 0x18, tls_record(22, b"\x02" + bytes(2400))))))
    req = b"POST /api HTTP/1.1\r\nHost: c2\r\nUser-Agent: Mozilla/5.0\r\nContent-Length: 600\r\n\r\n" + bytes(600)
    w.pkt(eth(mac, "02:00:00:00:00:01", 0x0800, ipv4(src, dst, 6, tcp(sport, port, seq + 3, 1, 0x18, tls_record(23, req)))))
    w.pkt(eth("02:00:00:00:00:01", mac, 0x0800, ipv4(dst, src, 6, tcp(port, sport, 3, seq + 3, 0x18, tls_record(23, bytes(700))))))
    w.pkt(eth(mac, "02:00:00:00:00:01", 0x0800, ipv4(src, dst, 6, tcp(sport, port, seq + 4, 1, 0x11))))


def http_short_flow(w, i, port):
    src, dst = flow_key(i)
    sport = 20000 + (i % 20000)
    mac = "02:00:00:00:%02x:%02x" % ((i >> 8) & 0xFF, i & 0xFF)
    seq = i * 500
    w.pkt(eth(mac, "02:00:00:00:00:01", 0x0800, ipv4(src, dst, 6, tcp(sport, port, seq, 0, 0x02))))
    w.pkt(eth("02:00:00:00:00:01", mac, 0x0800, ipv4(dst, src, 6, tcp(port, sport, 1, seq + 1, 0x12))))
    req = b"GET / HTTP/1.1\r\nHost: web\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
    w.pkt(eth(mac, "02:00:00:00:00:01", 0x0800, ipv4(src, dst, 6, tcp(sport, port, seq + 1, 1, 0x18, req))))
    resp = b"HTTP/1.1 200 OK\r\nContent-Length: 400\r\n\r\n" + bytes(400)
    w.pkt(eth("02:00:00:00:00:01", mac, 0x0800, ipv4(dst, src, 6, tcp(port, sport, 2, seq + 1 + len(req), 0x18, resp))))
    w.pkt(eth(mac, "02:00:00:00:00:01", 0x0800, ipv4(src, dst, 6, tcp(sport, port, seq + 2, 1, 0x11))))


def udp_beacon(w, i, port):
    src, dst = flow_key(i)
    sport = 50000 + (i % 10000)
    mac = "02:00:00:00:%02x:%02x" % ((i >> 8) & 0xFF, i & 0xFF)
    payload = bytes(48)
    w.pkt(eth(mac, "02:00:00:00:00:01", 0x0800, ipv4(src, dst, 17, struct.pack("!HHHH", sport, port, 56, 0) + payload)))


def main():
    total = int(sys.argv[1]) if len(sys.argv) > 1 else 100_000
    out = sys.argv[2] if len(sys.argv) > 2 else os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "out", "bench.pcap")
    w = PcapWriter(out)
    i = 0
    # flow-generating packets are ~7-17 per flow; iterate until packet budget
    while i < total:
        r = random.random()
        if r < 0.18:
            behinder_flow(w, i, 8443)
            i += 15
        elif r < 0.45:
            https_beacon_flow(w, i, 8445, b"bench-c2.local")
            i += 8
        elif r < 0.72:
            http_short_flow(w, i, 8080)
            i += 6
        elif r < 0.82:
            udp_beacon(w, i, 8455)
            i += 1
        else:
            http_short_flow(w, i, 8080 + (i % 4))
            i += 6
    w.close()
    size = os.path.getsize(out)
    print(f"wrote {i} packets -> {out} ({size/1e6:.1f} MB)")


if __name__ == "__main__":
    main()
