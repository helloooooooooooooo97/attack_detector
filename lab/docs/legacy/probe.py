#!/usr/bin/env python3
"""
Behinder (ice scorpion) real-time behavioral probe.

Deploy this on a Linux sensor attached to a switch mirror (SPAN/TAP) port.
It captures live traffic with AF_PACKET (no libpcap dependency), reconstructs
TLS flows, and applies the fingerprint rules validated in lab/detect.py:

  R1  memory-shell pattern  : many short flows, one exchange each, ~13 TLS
                              records, big request chunks, request > response
  R2  file-webshell pattern : one long-lived flow, many exchanges, constant
                              ~8225B request chunks
  JA3 signal                : reported separately (low confidence)

Everything is extracted from the encrypted-traffic side channel: TLS record
headers (type/length are plaintext), connection lifecycle and timing. No
decryption is performed.

Usage:
  sudo python3 probe.py -i eth0                 # live mirror port
  python3 probe.py -r capture.pcap              # offline replay / testing
  sudo python3 probe.py -i eth0 --json          # machine-readable alerts

Requirements: Linux (AF_PACKET) + Python 3.8+, no third-party packages.
"""

import argparse
import json
import socket
import struct
import sys
import time
from collections import defaultdict

import analyze
import detect


# --------------------------------------------------------------------------
# flow tracking
# --------------------------------------------------------------------------

class FlowTracker:
    """Reconstructs TCP flows from a packet stream and scores them."""

    def __init__(self, idle_timeout=30.0, max_flows=100_000):
        self.idle_timeout = idle_timeout
        self.max_flows = max_flows
        self.flows = {}
        self.order = []
        self.evicted = []  # (evict_ts, flow_features)
        self.ja3_by_flow = {}

    def packet(self, ts, src, dst, sport, dport, flags, payload):
        if sport == dport:
            return  # loopback edge case: same ports would corrupt the key
        key = frozenset(((src, sport), (dst, dport)))

        if flags & 0x02 and not (flags & 0x10):  # SYN opens a new connection
            self.flows[key] = self._new_flow(ts)
            self._touch(key)
            return

        flow = self.flows.get(key)
        if flow is None:
            flow = self.flows[key] = self._new_flow(ts)
            self._touch(key)
        flow["last"] = ts

        direction = "C" if dport == 8443 else "S" if sport == 8443 else None
        if direction is None:
            # probe is port-agnostic for scoring, but request/response
            # directionality needs to know which side is the server. We
            # conservatively treat the first data sender as the client.
            if not flow["client_dir"]:
                flow["client_dir"] = direction = "C"
            else:
                direction = "S"
            if sport == 443 or dport == 443 or dport == 8443:
                direction = "C" if dport in (443, 8443) else "S"

        if flags & 0x01:
            flow["fins"] += 1
        if payload:
            flow["segments"][direction].append((ts, payload))
        self._touch(key)

    def _new_flow(self, ts):
        return {
            "segments": {"C": [], "S": []},
            "first": ts,
            "last": ts,
            "syn": ts,
            "fins": 0,
            "client_dir": None,
        }

    def _touch(self, key):
        # keep an LRU-ish order so eviction is cheap
        if self.order and self.order[-1] != key:
            self.order.remove(key)
            self.order.append(key)

    def evict_idle(self, now):
        cutoff = now - self.idle_timeout
        victim = [k for k in list(self.flows) if self.flows[k]["last"] < cutoff]
        for k in victim:
            self._score_and_evict(k, now)
        if len(self.flows) > self.max_flows:
            for k in self.order[: len(self.flows) - self.max_flows]:
                self._score_and_evict(k, now)

    def flush_all(self, now):
        for k in list(self.flows):
            self._score_and_evict(k, now)

    def _score_and_evict(self, key, now):
        flow = self.flows.pop(key, None)
        if not flow or not flow["segments"]["C"]:
            return
        conn = self._to_analyze_result(key, flow)
        feat = detect.flow_features(conn)
        self.evicted.append((now, feat, conn["ja3"]))

    def _to_analyze_result(self, key, flow):
        recs = {
            d: list(analyze.tls_records(flow["segments"][d]))
            for d in ("C", "S")
        }
        ja3 = None
        for rtype, ver, ts, payload in recs["C"]:
            if rtype == 22:
                ja3 = analyze.ja3_from_clienthello(payload)
                break
        appdata = []
        for direction, rlist in recs.items():
            for rtype, ver, ts, payload in rlist:
                if rtype == 23:
                    appdata.append((ts, direction, len(payload)))
        appdata.sort(key=lambda x: x[0])
        conn = {
            "conn": "flow",
            "first": flow["first"],
            "last": flow["last"],
            "tls_records": {d: len(r) for d, r in recs.items()},
            "ja3": ja3,
            "exchanges": self._exchanges(appdata),
        }
        return conn

    @staticmethod
    def _exchanges(appdata):
        # same run-grouping as analyze.py (shared constants)
        runs = []
        for ts, direction, size in appdata:
            if (
                runs
                and runs[-1]["dir"] == direction
                and ts - runs[-1]["end"] <= analyze.EXCHANGE_GAP
            ):
                runs[-1]["records"] += 1
                runs[-1]["bytes"] += size
                runs[-1]["sizes"].append(size)
                runs[-1]["end"] = ts
            else:
                runs.append(
                    {"dir": direction, "start": ts, "end": ts,
                     "records": 1, "bytes": size, "sizes": [size]}
                )
        exchanges = []
        i = 0
        while i < len(runs) - 1:
            if (
                runs[i]["dir"] == "C"
                and runs[i + 1]["dir"] == "S"
                and (runs[i]["bytes"] >= 1000 or runs[i + 1]["bytes"] >= 1000)
            ):
                exchanges.append(
                    {"req_records": runs[i]["records"],
                     "req_bytes": runs[i]["bytes"],
                     "req_sizes": runs[i]["sizes"],
                     "resp_records": runs[i + 1]["records"],
                     "resp_bytes": runs[i + 1]["bytes"],
                     "resp_sizes": runs[i + 1]["sizes"],
                     "start": runs[i]["start"],
                     "end": runs[i + 1]["end"]}
                )
                i += 2
            else:
                i += 1
        return exchanges


# --------------------------------------------------------------------------
# live capture (AF_PACKET, Linux)
# --------------------------------------------------------------------------

def live_capture(tracker, iface):
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    sock.bind((iface, 0))
    print(f"[probe] listening on {iface}", file=sys.stderr)
    last_evict = time.time()
    while True:
        try:
            data = sock.recv(65535)
        except KeyboardInterrupt:
            break
        now = time.time()
        pkt = analyze.parse_ip_tcp(data, 1)  # AF_PACKET delivers Ethernet frames
        if pkt:
            src, dst, sport, dport, flags, payload = pkt
            tracker.packet(now, src, dst, sport, dport, flags, payload)
        if now - last_evict >= 1.0:
            tracker.evict_idle(now)
            last_evict = now


# --------------------------------------------------------------------------
# replay mode (pcap file, for testing / offline analysis)
# --------------------------------------------------------------------------

def replay_capture(tracker, path):
    print(f"[probe] replaying {path}", file=sys.stderr)
    for ts, data, linktype in analyze.read_pcap(path):
        pkt = analyze.parse_ip_tcp(data, linktype)
        if pkt:
            src, dst, sport, dport, flags, payload = pkt
            tracker.packet(ts, src, dst, sport, dport, flags, payload)
    tracker.flush_all(time.time())


# --------------------------------------------------------------------------
# alerting
# --------------------------------------------------------------------------

class AlertEmitter:
    def __init__(self, window=60.0, min_mem_flows=3, json_out=False,
                 report_ja3=True):
        self.window = window
        self.min_mem_flows = min_mem_flows
        self.json_out = json_out
        self.report_ja3 = report_ja3
        self.mem_hits = []          # (ts, src_ip, feat)
        self.last_agg_alert = {}    # src_ip -> ts

    def emit(self, event, **fields):
        fields["event"] = event
        fields["ts"] = time.time()
        if self.json_out:
            print(json.dumps(fields, ensure_ascii=False))
        else:
            loc = f"{fields.get('src_ip','?')}:{fields.get('sport','?')} -> " \
                  f"{fields.get('dst_ip','?')}:{fields.get('dport','?')}"
            print(f"[{time.strftime('%H:%M:%S')}] {event:<28} {loc}")
        sys.stdout.flush()

    def on_evicted_flow(self, now, feat, ja3, conn):
        src_ip = self._src_ip(conn)
        if detect.r1_mem_shell(feat):
            self.emit(
                "behinder.mem_shell_flow",
                src_ip=src_ip, sport=feat.get("sport"),
                dst_ip=feat.get("dst_ip"), dport=feat.get("dport"),
                exchanges=feat["exchanges"], records=feat["records"],
                req_bytes=feat["req_bytes"], resp_bytes=feat["resp_bytes"],
                big_req=feat["big_req"], duration=round(feat["duration"], 2),
            )
            self.mem_hits.append((now, src_ip, feat))
        elif detect.r2_file_shell(feat):
            self.emit(
                "behinder.file_webshell_flow",
                src_ip=src_ip, sport=feat.get("sport"),
                dst_ip=feat.get("dst_ip"), dport=feat.get("dport"),
                exchanges=feat["exchanges"], records=feat["records"],
                req_bytes=feat["req_bytes"], resp_bytes=feat["resp_bytes"],
                chunks_8225=feat["chunks_8225"],
            )
        if self.report_ja3 and ja3:
            self.emit(
                "tls.ja3_signal",
                src_ip=src_ip, ja3=ja3,
                note="low-confidence: shared by normal Java/OkHttp clients",
            )

    def aggregate(self, now):
        cutoff = now - self.window
        self.mem_hits = [h for h in self.mem_hits if h[0] >= cutoff]
        by_src = defaultdict(int)
        for _ts, src, _feat in self.mem_hits:
            by_src[src] += 1
        for src, n in by_src.items():
            if (
                n >= self.min_mem_flows
                and now - self.last_agg_alert.get(src, 0) >= self.window
            ):
                self.last_agg_alert[src] = now
                self.emit(
                    "behinder.memory_shell_aggregate",
                    src_ip=src, flows=n, window=int(self.window),
                    note="short single-exchange TLS flows with big request chunks",
                )

    @staticmethod
    def _src_ip(conn):
        # flows are keyed anonymously; keep it simple: client is the flow's
        # first-seen source. Tracked separately in live mode.
        return conn.get("client_ip") or "unknown"


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-i", "--iface", help="interface to listen on (mirror/SPAN port)")
    ap.add_argument("-r", "--replay", help="pcap file to replay instead of live capture")
    ap.add_argument("--window", type=float, default=60.0,
                    help="aggregation window in seconds (default 60)")
    ap.add_argument("--min-mem-flows", type=int, default=3,
                    help="min memory-shell flows per src within window (default 3)")
    ap.add_argument("--idle", type=float, default=30.0,
                    help="flow idle timeout in seconds (default 30)")
    ap.add_argument("--json", action="store_true",
                    help="emit alerts as JSON lines")
    ap.add_argument("--no-ja3", action="store_true",
                    help="do not report low-confidence JA3 signals")
    args = ap.parse_args()

    if not args.iface and not args.replay:
        ap.error("need -i <iface> or -r <pcap>")

    tracker = FlowTracker(idle_timeout=args.idle)
    emitter = AlertEmitter(
        window=args.window,
        min_mem_flows=args.min_mem_flows,
        json_out=args.json,
        report_ja3=not args.no_ja3,
    )

    def handle_evicted():
        for ev_ts, feat, ja3 in tracker.evicted:
            emitter.on_evicted_flow(ev_ts, feat, ja3, {})
        tracker.evicted.clear()
        emitter.aggregate(time.time())

    try:
        if args.replay:
            replay_capture(tracker, args.replay)
            handle_evicted()
        else:
            live_capture(tracker, args.iface)
            tracker.flush_all(time.time())
            handle_evicted()
    except KeyboardInterrupt:
        tracker.flush_all(time.time())
        handle_evicted()
        print("[probe] stopped", file=sys.stderr)


if __name__ == "__main__":
    main()
