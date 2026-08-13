#!/usr/bin/env python3
"""Generate hard normal-traffic pcaps targeting the two diagnosed A-test FPs:
  - non-TLS long connections to high ports (real_traffic3 #60871 shape)
  - server-side :443 connection attempts / small TLS sessions (sr shape)

Additive: uses gen_normal.py's packet builders; writes data/captures/normal_*.
"""

import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gen_normal import (Pcap, SNIS, client_hello, eth, flow_pair, ipv4,  # noqa
                        tcp, tls_pair, tls_rec)

random.seed(20260813)


def gen_hard_nonTLS(w, i):
    """Non-TLS long connection to a high port, moderate payload, 5-30s."""
    src, dst = flow_pair(i + 9000)
    sport = 30000 + i
    dport = random.choice([60000, 60100, 60871, 62000, 64000, 55555])
    seq = i * 7777 + 10
    w.pkt(eth(ipv4(src, dst, 6, tcp(sport, dport, seq, 0, 0x02))))
    w.pkt(eth(ipv4(dst, src, 6, tcp(dport, sport, 1, seq + 1, 0x12))))
    w.pkt(eth(ipv4(src, dst, 6, tcp(sport, dport, seq + 1, 1, 0x10))))
    ack = seq + 2
    k = 0
    for _ in range(random.randint(4, 12)):
        req = bytes(random.randint(200, 5000))
        resp = bytes(random.randint(100, 8000))
        w.pkt(eth(ipv4(src, dst, 6, tcp(sport, dport, ack, 1, 0x18, req))),
              random.uniform(0.2, 3.0))
        ack += len(req)
        w.pkt(eth(ipv4(dst, src, 6, tcp(dport, sport, k + 2, ack, 0x18, resp))),
              random.uniform(0.01, 0.5))
        ack += len(resp)
        k += 1
    w.pkt(eth(ipv4(src, dst, 6, tcp(sport, dport, ack, 1, 0x11))), 0.001)


def gen_hard_srv443(w, i):
    """Server-side :443 flows: attempts without payload, failed SYNs, small TLS."""
    src, dst = flow_pair(i + 12000)
    src, dst = dst, src  # client -> server:443
    sport = 20000 + i
    seq = i * 500
    mode = i % 3
    if mode == 0:  # handshake, no payload, clean close
        w.pkt(eth(ipv4(src, dst, 6, tcp(sport, 443, seq, 0, 0x02))))
        w.pkt(eth(ipv4(dst, src, 6, tcp(443, sport, 1, seq + 1, 0x12))))
        w.pkt(eth(ipv4(src, dst, 6, tcp(sport, 443, seq + 1, 1, 0x10))))
        w.pkt(eth(ipv4(src, dst, 6, tcp(sport, 443, seq + 2, 1, 0x11))), 0.5)
    elif mode == 1:  # SYN -> RST (failed attempt)
        w.pkt(eth(ipv4(src, dst, 6, tcp(sport, 443, seq, 0, 0x02))))
        w.pkt(eth(ipv4(dst, src, 6, tcp(443, sport, 1, seq + 1, 0x14))))
    else:  # small TLS session
        tls_pair(w, src, dst, sport, 443, seq, random.choice(SNIS),
                 [random.randint(100, 400)])


def main():
    out = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "data", "captures")
    os.makedirs(out, exist_ok=True)
    n_long = 200
    n_srv = 200
    w = Pcap(os.path.join(out, "normal_hard_nonTLS_long.pcap"))
    for i in range(n_long):
        gen_hard_nonTLS(w, i)
    w.close()
    w = Pcap(os.path.join(out, "normal_hard_srv443.pcap"))
    for i in range(n_srv):
        gen_hard_srv443(w, i)
    w.close()
    print(f"generated {n_long} non-TLS long + {n_srv} srv443 flows")


if __name__ == "__main__":
    main()
