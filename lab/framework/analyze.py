#!/usr/bin/env python3
"""
Analyze Behinder TLS traffic captures produced by lab_entry.sh.

Reproduces the four fingerprint dimensions from the 观成科技 article
"冰蝎内存马加密流量分析":
  1. connection reuse strategy   (TCP flows vs exchanges per connection)
  2. TLS record size distribution
  3. multi-flow timing           (inter-flow gaps, overlap)
  4. TLS handshake fingerprint   (JA3)

Usage: analyze.py <cap_keepalive.pcap> <cap_close.pcap> [out_dir]
"""

import json
import os
import struct
import sys
from collections import defaultdict

SERVER_PORT = 8443
EXCHANGE_GAP = 1.0  # seconds: gap that separates request/response cycles on one conn


# --------------------------------------------------------------------------
# pcap reading
# --------------------------------------------------------------------------

def read_pcap(path):
    """Yield (ts_seconds, packet_bytes) for a classic pcap file."""
    with open(path, "rb") as f:
        magic = f.read(4)
        if magic == b"\xd4\xc3\xb2\xa1":
            endian, ts_div = "<", 1_000_000.0
        elif magic == b"\xa1\xb2\xc3\xd4":
            endian, ts_div = ">", 1_000_000.0
        elif magic == b"\x4d\x3c\xb2\xa1":
            endian, ts_div = "<", 1_000_000_000.0
        elif magic == b"\xa1\xb2\x3c\x4d":
            endian, ts_div = ">", 1_000_000_000.0
        else:
            raise SystemExit(f"unsupported pcap magic: {magic!r}")

        ver_maj, ver_min, _, _, snaplen, linktype = struct.unpack(
            endian + "HHIIII", f.read(20)
        )
        print(f"[pcap] {path}: linktype={linktype} snaplen={snaplen}")

        while True:
            hdr = f.read(16)
            if len(hdr) < 16:
                break
            ts_sec, ts_frac, incl_len, _orig_len = struct.unpack(
                endian + "IIII", hdr
            )
            data = f.read(incl_len)
            if len(data) < incl_len:
                break
            yield ts_sec + ts_frac / ts_div, data, linktype


def parse_ip_tcp(data, linktype):
    """Return (src_ip, dst_ip, sport, dport, tcp_flags, tcp_payload) or None."""
    if linktype == 1:  # Ethernet
        if len(data) < 14:
            return None
        ethertype = struct.unpack("!H", data[12:14])[0]
        off = 14
        if ethertype == 0x8100:  # VLAN
            off += 4
            ethertype = struct.unpack("!H", data[16:18])[0]
    elif linktype in (12, 101):  # RAW IP
        ethertype = (data[0] >> 4) & 0xF
        ethertype = 4 if ethertype == 4 else 6
        off = 0
    elif linktype == 0:  # BSD loopback
        off = 4
        ethertype = 4
    elif linktype == 113:  # Linux cooked v1
        off = 16
        ethertype = struct.unpack("!H", data[14:16])[0]
    elif linktype == 276:  # Linux cooked v2
        off = 20
        ethertype = struct.unpack("!H", data[0:2])[0]
    else:
        return None

    if ethertype == 0x0800:
        ip_ver = (data[off] >> 4) & 0xF
        if ip_ver != 4:
            return None
        ihl = (data[off] & 0xF) * 4
        proto = data[off + 9]
        src = socket_ntoa(data[off + 12 : off + 16])
        dst = socket_ntoa(data[off + 16 : off + 20])
        l4 = off + ihl
    elif ethertype == 0x86DD:
        proto = data[off + 6]
        src = ipv6_ntoa(data[off + 8 : off + 24])
        dst = ipv6_ntoa(data[off + 24 : off + 40])
        l4 = off + 40
    else:
        return None

    if proto != 6 or len(data) < l4 + 20:
        return None
    sport, dport = struct.unpack("!HH", data[l4 : l4 + 4])
    flags = data[l4 + 13]
    doff = ((data[l4 + 12] >> 4) & 0xF) * 4
    payload = data[l4 + doff :]
    return src, dst, sport, dport, flags, payload


def socket_ntoa(b):
    return ".".join(str(x) for x in b)


def ipv6_ntoa(b):
    return ":".join(f"{int.from_bytes(b[i:i+2],'big'):x}" for i in range(0, 16, 2))


# --------------------------------------------------------------------------
# TLS record parsing
# --------------------------------------------------------------------------

def tls_records(segments):
    """Walk reassembled TLS stream; yield (record_type, version, ts, payload)."""
    buf = bytearray()
    for ts, payload in segments:
        buf += payload
        while len(buf) >= 5:
            rtype, ver, rlen = struct.unpack("!BHH", bytes(buf[:5]))
            if rlen > 18_000:
                break
            if len(buf) < 5 + rlen:
                break
            yield rtype, ver, ts, bytes(buf[5 : 5 + rlen])
            del buf[: 5 + rlen]


def ja3_from_clienthello(payload):
    """Compute JA3 from a TLS 1.2/1.3 ClientHello record payload."""
    if len(payload) < 5 or payload[0] != 1:
        return None
    msg_len = int.from_bytes(payload[1:4], "big")
    body = payload[4 : 4 + msg_len]
    if len(body) < 38:
        return None
    ver = int.from_bytes(body[0:2], "big")
    pos = 2 + 32
    if pos >= len(body):
        return None
    sid_len = body[pos]
    pos += 1 + sid_len
    if pos + 2 > len(body):
        return None
    cs_len = int.from_bytes(body[pos : pos + 2], "big")
    pos += 2
    ciphers = [
        int.from_bytes(body[i : i + 2], "big")
        for i in range(pos, min(pos + cs_len, len(body) - 1), 2)
    ]
    pos += cs_len
    if pos >= len(body):
        return None
    comp_len = body[pos]
    pos += 1 + comp_len

    extensions = {}
    if pos + 2 <= len(body):
        ext_total = int.from_bytes(body[pos : pos + 2], "big")
        pos += 2
        end = min(pos + ext_total, len(body))
        while pos + 4 <= end:
            etype = int.from_bytes(body[pos : pos + 2], "big")
            elen = int.from_bytes(body[pos + 2 : pos + 4], "big")
            edata = body[pos + 4 : pos + 4 + elen]
            extensions[etype] = edata
            pos += 4 + elen

    groups = []
    if 10 in extensions:
        gdata = extensions[10]
        if len(gdata) >= 2:
            glen = int.from_bytes(gdata[:2], "big")
            groups = [
                int.from_bytes(gdata[2 + i : 4 + i], "big")
                for i in range(0, min(glen, len(gdata) - 2), 2)
            ]

    ecpf = []
    if 11 in extensions:
        ecpf = list(extensions[11][1:])

    return (
        f"{ver},"
        f"{'-'.join(map(str, ciphers))},"
        f"{'-'.join(map(str, sorted(extensions)))},"
        f"{'-'.join(map(str, groups))},"
        f"{'-'.join(map(str, ecpf))}"
    )


# --------------------------------------------------------------------------
# per-connection analysis
# --------------------------------------------------------------------------

def analyze_capture(path, server_port=8443):
    # Full 4-tuple tracking with SYN segmentation. Loopback traffic has the
    # same IP on both sides, so the canonical key is the port pair; a new SYN
    # resets the record (ephemeral ports get reused quickly).
    conns = {}          # canonical key -> record
    order = []          # canonical keys in first-seen order

    for ts, data, linktype in read_pcap(path):
        pkt = parse_ip_tcp(data, linktype)
        if pkt is None:
            continue
        src, dst, sport, dport, flags, payload = pkt
        if sport == server_port or dport == server_port:
            key = frozenset(((src, sport), (dst, dport)))
            if flags & 0x02 and not (flags & 0x10):
                # TCP SYN: new connection (may reuse a previously seen port pair)
                conns[key] = {
                    "segments": {"C": [], "S": []},
                    "first": None, "last": None, "syn_ts": ts,
                    "fins": 0,
                }
                if key not in order:
                    order.append(key)
            c = conns.setdefault(
                key,
                {"segments": {"C": [], "S": []}, "first": None,
                 "last": None, "syn_ts": ts, "fins": 0},
            )
            if key not in order:
                order.append(key)
            if c["first"] is None:
                c["first"] = ts
            c["last"] = ts
            if flags & 0x01:
                c["fins"] += 1
            direction = "C" if dport == server_port else "S"
            c["segments"][direction].append((ts, payload))

    results = []
    all_ja3 = set()
    for key in order:
        c = conns[key]
        recs = {"C": list(tls_records(c["segments"]["C"])),
                "S": list(tls_records(c["segments"]["S"]))}

        ja3 = None
        for rtype, ver, ts, payload in recs["C"]:
            if rtype == 22:
                ja3 = ja3_from_clienthello(payload)
                if ja3:
                    all_ja3.add(ja3)
                break

        # chronological app-data records: (ts, dir, size)
        appdata = []
        for direction, rlist in recs.items():
            for rtype, ver, ts, payload in rlist:
                if rtype == 23:
                    appdata.append((ts, direction, len(payload)))
        appdata.sort(key=lambda x: x[0])

        # group into direction runs (request burst / response burst)
        runs = []
        for ts, direction, size in appdata:
            if runs and runs[-1]["dir"] == direction and ts - runs[-1]["end"] <= EXCHANGE_GAP:
                runs[-1]["records"] += 1
                runs[-1]["bytes"] += size
                runs[-1]["sizes"].append(size)
                runs[-1]["end"] = ts
            else:
                runs.append({"dir": direction, "start": ts, "end": ts,
                             "records": 1, "bytes": size, "sizes": [size]})

        # Count exchanges: a C->S run followed by an S->C run. The tiny
        # 85B/83B application-data records right after the handshake are JSSE's
        # encrypted Finished messages (TLS 1.2 sends them as record type 23),
        # not HTTP traffic, so at least one side of a real exchange must carry
        # a record >= 1000 B (Behinder: the 8225 B request chunk; normal
        # browsing: a multi-KB response).
        exchanges = []
        i = 0
        while i < len(runs) - 1:
            if (
                runs[i]["dir"] == "C"
                and runs[i + 1]["dir"] == "S"
                and (runs[i]["bytes"] >= 1000 or runs[i + 1]["bytes"] >= 1000)
            ):
                exchanges.append({
                    "req_records": runs[i]["records"],
                    "req_bytes": runs[i]["bytes"],
                    "req_sizes": runs[i]["sizes"],
                    "resp_records": runs[i + 1]["records"],
                    "resp_bytes": runs[i + 1]["bytes"],
                    "resp_sizes": runs[i + 1]["sizes"],
                    "start": runs[i]["start"],
                    "end": runs[i + 1]["end"],
                })
                i += 2
            else:
                i += 1

        ephemeral = [p for (_ip, p) in key if p != SERVER_PORT][0]
        label = str(ephemeral)
        results.append({
            "conn": label,
            "syn_ts": c["syn_ts"] or c["first"],
            "first": c["first"],
            "last": c["last"],
            "tls_records": {d: len(r) for d, r in recs.items()},
            "appdata_records": len(appdata),
            "ja3": ja3,
            "exchanges": exchanges,
        })

    return results, all_ja3


# --------------------------------------------------------------------------
# reporting
# --------------------------------------------------------------------------

def summarize(results):
    conns = results["conns"]
    n_conn = len(conns)
    n_exch = sum(len(c["exchanges"]) for c in conns)
    rec_counts = [sum(c["tls_records"].values()) for c in conns]
    exch_per_conn = [len(c["exchanges"]) for c in conns]

    all_sizes = []
    big_per_exchange = []
    for c in conns:
        for e in c["exchanges"]:
            all_sizes += e["req_sizes"] + e["resp_sizes"]
            big_per_exchange.append(
                sum(1 for s in e["req_sizes"] + e["resp_sizes"] if s >= 1000)
            )

    starts = sorted(c["syn_ts"] for c in conns)
    ends = {id(c): c["last"] for c in conns}
    gaps = []
    overlap = 0
    by_first = sorted(conns, key=lambda c: c["first"])
    for prev, nxt in zip(by_first, by_first[1:]):
        g = nxt["first"] - prev["last"]
        gaps.append(g)
        if g < 0:
            overlap += 1

    return {
        "connections": n_conn,
        "total_exchanges": n_exch,
        "exchanges_per_conn": exch_per_conn,
        "tls_records_per_conn": rec_counts,
        "appdata_sizes": all_sizes,
        "big_records_per_exchange": big_per_exchange,
        "inter_flow_gaps_s": [round(g, 3) for g in gaps],
        "overlapping_flow_pairs": overlap,
        "first_flow_start": by_first[0]["first"] if by_first else None,
        "last_flow_end": max(c["last"] for c in conns) if conns else None,
    }


def plot(scenarios, out_dir):
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, axes = plt.subplots(3, len(scenarios), figsize=(7 * len(scenarios), 11))
    colors = {"keepalive": "#2f80ed", "close": "#eb5757", "normal": "#27ae60"}

    for col, (name, res) in enumerate(scenarios.items()):
        conns = res["conns"]
        # 1) connection timeline (gantt)
        ax = axes[0][col]
        for i, c in enumerate(sorted(conns, key=lambda c: c["first"])):
            ax.barh(i, c["last"] - c["first"], left=c["first"] - res["t0"],
                    height=0.6, color=colors[name], alpha=0.85)
        ax.set_title(f"{name}: TCP flow timeline")
        ax.set_xlabel("seconds since first flow start")
        ax.set_ylabel("flow index")
        ax.grid(axis="x", alpha=0.3)

        # 2) TLS appdata record size distribution
        ax = axes[1][col]
        sizes = res["summary"]["appdata_sizes"]
        buckets = ["<100", "100-499", "500-999", "1k-4k", "4k-8k", "8k-16k"]
        counts = [
            sum(1 for s in sizes if s < 100),
            sum(1 for s in sizes if 100 <= s < 500),
            sum(1 for s in sizes if 500 <= s < 1000),
            sum(1 for s in sizes if 1000 <= s < 4096),
            sum(1 for s in sizes if 4096 <= s < 8192),
            sum(1 for s in sizes if s >= 8192),
        ]
        ax.bar(buckets, counts, color=colors[name], alpha=0.85)
        ax.set_title(f"{name}: TLS application-data record sizes")
        ax.set_ylabel("record count")
        for x, v in zip(range(len(buckets)), counts):
            ax.text(x, v, str(v), ha="center", va="bottom", fontsize=9)

        # 3) exchanges per connection
        ax = axes[2][col]
        epc = res["summary"]["exchanges_per_conn"]
        ax.bar(range(len(epc)), epc, color=colors[name], alpha=0.85)
        ax.set_title(f"{name}: exchanges per TCP connection "
                     f"(total {res['summary']['total_exchanges']})")
        ax.set_xlabel("connection index (by start time)")
        ax.set_ylabel("exchanges")
        ax.set_xticks(range(len(epc)))

    fig.suptitle(
        "Behinder v4.0.7 TLS traffic vs normal browsing "
        "(keep-alive / memory-shell-like / normal baseline)",
        fontsize=13,
    )
    fig.tight_layout(rect=(0, 0, 1, 0.97))
    out = os.path.join(out_dir, "behinder_fingerprints.png")
    fig.savefig(out, dpi=130)
    print(f"[plot] saved {out}")


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)

    # args: [label=path ...] [out_dir]
    pairs = []
    out_dir = None
    for arg in sys.argv[1:]:
        if "=" in arg:
            pairs.append(tuple(arg.split("=", 1)))
        elif out_dir is None:
            out_dir = arg
    if not pairs:
        raise SystemExit("usage: analyze.py [label=cap.pcap ...] [out_dir]")
    if out_dir is None:
        out_dir = os.path.dirname(pairs[0][1]) or "."

    scenarios = {}
    for name, path in pairs:
        conns, ja3s = analyze_capture(path)
        summary = summarize({"conns": conns})
        t0 = min((c["first"] for c in conns), default=0)
        scenarios[name] = {"conns": conns, "summary": summary, "ja3s": sorted(ja3s), "t0": t0}

    for name, res in scenarios.items():
        s = res["summary"]
        print("\n" + "=" * 70)
        print(f"SCENARIO: {name}")
        print("=" * 70)
        print(f"TCP connections          : {s['connections']}")
        print(f"Total exchanges          : {s['total_exchanges']}")
        print(f"Exchanges per connection : {s['exchanges_per_conn']}")
        print(f"TLS records per conn     : {s['tls_records_per_conn']}")
        print(f"App-data records total   : {len(s['appdata_sizes'])}")
        print(f"Big records per exchange : {s['big_records_per_exchange']}")
        print(f"Inter-flow gaps (s)      : {s['inter_flow_gaps_s']}")
        print(f"Overlapping flow pairs   : {s['overlapping_flow_pairs']}")
        print(f"JA3(s)                   : {res['ja3s']}")

        # example: first 3 exchanges of the first connection
        if res["conns"]:
            c0 = sorted(res["conns"], key=lambda c: c["first"])[0]
            print(f"First connection detail ({c0['conn']}):")
            for j, e in enumerate(c0["exchanges"][:4]):
                print(f"  exch{j}: req={e['req_records']} rec "
                      f"({e['req_bytes']}B, sizes={e['req_sizes']}) -> "
                      f"resp={e['resp_records']} rec "
                      f"({e['resp_bytes']}B, sizes={e['resp_sizes']})")

    with open(os.path.join(out_dir, "fingerprints.json"), "w") as f:
        json.dump(
            {
                name: {
                    "summary": res["summary"],
                    "ja3": res["ja3s"],
                    "connections": [
                        {
                            "conn": c["conn"],
                            "first": c["first"] - res["t0"],
                            "last": c["last"] - res["t0"],
                            "tls_records": c["tls_records"],
                            "exchanges": [
                                {k: v for k, v in e.items() if k != "sizes"}
                                for e in c["exchanges"]
                            ],
                        }
                        for c in sorted(res["conns"], key=lambda c: c["first"])
                    ],
                }
                for name, res in scenarios.items()
            },
            f,
            indent=2,
        )
    print(f"\n[json] saved {os.path.join(out_dir, 'fingerprints.json')}")

    plot(scenarios, out_dir)


if __name__ == "__main__":
    main()
