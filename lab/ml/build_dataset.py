#!/usr/bin/env python3
"""Build the labeled flow-sequence dataset from lab pcaps.

For every flow in the tool captures (malicious) and the normal captures:
  events : (dir, size_bucket, dt_bucket) sequence, padded to MAX_LEN
  meta   : [is_tls, has_sni, sni_bucket, duration, tot_c, tot_s, n_events, dport]
  label  : 1 malicious / 0 normal
  tool   : tool id ("" for normal)

Output: ml/data/dataset.pt
"""

import collections
import os
import struct
import sys

import numpy as np
import torch

LAB = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_DIR = os.path.join(LAB, "out")
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
MAX_LEN = 96
BF_WINDOW = 10.0  # cross-flow burst window (seconds)


def parse_pkt(data, linktype):
    off = 0
    ether = 0
    if linktype == 1:
        if len(data) < 14:
            return None
        ether = struct.unpack("!H", data[12:14])[0]
        off = 14
        if ether in (0x8100, 0x88A8):
            if len(data) < off + 4:
                return None
            ether = struct.unpack("!H", data[off + 2:off + 4])[0]
            off += 4
    elif linktype == 0:
        off = 4
        ether = 0x0800
    else:
        ether = 0x0800
    if ether == 0x0800:
        if len(data) < off + 20 or data[off] >> 4 != 4:
            return None
        ihl = (data[off] & 0x0F) * 4
        proto = data[off + 9]
        if proto not in (6, 17):
            return None
        src = ".".join(str(b) for b in data[off + 12:off + 16])
        dst = ".".join(str(b) for b in data[off + 16:off + 20])
        l4 = off + ihl
    elif ether == 0x86DD:
        if len(data) < off + 40:
            return None
        proto = data[off + 6]
        if proto not in (6, 17):
            return None
        src = ":".join(f"{b:02x}" for b in data[off + 8:off + 24])
        dst = ":".join(f"{b:02x}" for b in data[off + 24:off + 40])
        l4 = off + 40
    else:
        return None
    if len(data) < l4 + 8:
        return None
    sport, dport = struct.unpack("!HH", data[l4:l4 + 4])
    if proto == 17:
        ul = struct.unpack("!H", data[l4 + 4:l4 + 6])[0]
        if ul < 8 or l4 + ul > len(data):
            return None
        payload = data[l4 + 8:l4 + ul]
        return src, sport, dst, dport, proto, payload
    if len(data) < l4 + 20:
        return None
    doff = (data[l4 + 12] >> 4) * 4
    if doff < 20 or l4 + doff > len(data):
        return None
    payload = data[l4 + doff:]
    return src, sport, dst, dport, proto, payload


def read_pcap(path):
    with open(path, "rb") as f:
        magic = f.read(4)
        if len(magic) != 4:
            return
        endian, div = "<", 1_000_000.0
        if magic == b"\xd4\xc3\xb2\xa1":
            pass
        elif magic == b"\xa1\xb2\xc3\xd4":
            endian = ">"
        elif magic == b"\x4d\x3c\xb2\xa1":
            div = 1_000_000_000.0
        elif magic == b"\xa1\xb2\x3c\x4d":
            endian = ">"
            div = 1_000_000_000.0
        else:
            return
        hdr = f.read(20)
        if len(hdr) != 20:
            return
        linktype = struct.unpack(endian + "I", hdr[16:20])[0]
        while True:
            rec = f.read(16)
            if len(rec) != 16:
                return
            sec, usec, incl, _ = struct.unpack(endian + "IIII", rec)
            data = f.read(incl)
            if len(data) < incl:
                return
            yield sec + usec / div, data, linktype


def sni_from_ch(data):
    """SNI from a ClientHello handshake message (record header stripped)."""
    if len(data) < 5 or data[0] != 1:
        return None
    ml = int.from_bytes(data[1:4], "big")
    b = data[4:4 + ml]
    if len(b) < 38:
        return None
    pos = 2 + 32
    sl = b[pos]
    pos += 1 + sl
    cs = int.from_bytes(b[pos:pos + 2], "big")
    pos += 2 + cs
    cl = b[pos]
    pos += 1 + cl
    if pos + 2 > len(b):
        return None
    ext_total = int.from_bytes(b[pos:pos + 2], "big")
    pos += 2
    end = min(pos + ext_total, len(b))
    while pos + 4 <= end:
        et = int.from_bytes(b[pos:pos + 2], "big")
        el = int.from_bytes(b[pos + 2:pos + 4], "big")
        if pos + 4 + el > end:
            break
        d = b[pos + 4:pos + 4 + el]
        if et == 0 and len(d) >= 5 and d[2] == 0:
            nl = int.from_bytes(d[3:5], "big")
            if 5 + nl <= len(d):
                return d[5:5 + nl].decode(errors="ignore")
        pos += 4 + el
    return None


def size_bucket(sz):
    return 0 if sz <= 0 else min(31, int(sz).bit_length() - 1)


DT_EDGES = [0.001, 0.005, 0.02, 0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0]


def dt_bucket(dt):
    for i, e in enumerate(DT_EDGES):
        if dt <= e:
            return i
    return len(DT_EDGES)


def sni_bucket(sni):
    return 0 if not sni else 1 + (abs(hash(sni)) % 127)


def extract_flows(path):
    conns = collections.defaultdict(lambda: {
        "c": [], "s": [], "first": None, "last": None, "client": None,
        "server": None,
        "dport": 0, "proto": 0})
    for ts, data, lt in read_pcap(path):
        pkt = parse_pkt(data, lt)
        if pkt is None:
            continue
        src, sport, dst, dport, proto, payload = pkt
        key = frozenset(((src, sport), (dst, dport), proto))
        c = conns[key]
        c["proto"] = proto
        if c["first"] is None:
            c["first"] = ts
            c["client"] = (src, sport)
            c["dport"] = dport
        c["last"] = ts
        if (src, sport) == c["client"]:
            c["c"].append((ts, payload))
        else:
            if c["server"] is None:
                c["server"] = (src, sport)
            c["s"].append((ts, payload))
    flows = []
    for c in conns.values():
        if not c["c"] and not c["s"]:
            continue
        flows.append(c)
    return flows


def flow_meta(c):
    c_bytes = sum(len(p) for _, p in c["c"])
    s_bytes = sum(len(p) for _, p in c["s"])
    is_tls = 0.0
    sni = None
    for _, p in c["c"][:5]:
        if len(p) >= 3 and p[0] == 0x16 and p[1] == 0x03:
            is_tls = 1.0
            if len(p) >= 5:
                rec = p[5:]
                if rec and rec[0] == 1:
                    sni = sni_from_ch(rec)
            break
    dur = max(0.0, (c["last"] or 0) - (c["first"] or 0))
    n_ev = float(sum(1 for _, p in c["c"] if p) + sum(1 for _, p in c["s"] if p))
    return [
        is_tls,
        1.0 if sni else 0.0,
        np.log1p(dur),
        np.log1p(c_bytes), np.log1p(s_bytes),
        np.log1p(n_ev),
        min(1.0, c["dport"] / 65535.0),
        0.0,  # same_port_burst (filled in cross-flow pass)
        0.0,  # ports_sweep (filled in cross-flow pass)
    ]


def events_of(c):
    evs = [(0, ts, len(p)) for ts, p in c["c"] if p]
    evs += [(1, ts, len(p)) for ts, p in c["s"] if p]
    evs.sort(key=lambda e: e[1])
    if not evs:
        # payload-less connection (e.g. SYN probe): keep a zero-data marker
        return [(0, 0, 0.0)]
    out = []
    prev = None
    for d, ts, sz in evs:
        dt = 0.0 if prev is None else ts - prev
        prev = ts
        out.append((d, sz, dt))
    return out


def cross_flow_meta(flows, metas):
    """Fill meta[7] (same dst-port burst count) and meta[8] (distinct-ports
    sweep) within a rolling window around each flow."""
    for i, f in enumerate(flows):
        t = f["first"]
        dport = f["dport"]
        src = (f.get("client") or (None, 0))[0]
        dst = (f.get("server") or (None, 0))[0]
        same_port = 0
        sweep = set()
        for j in range(len(flows)):
            if j == i:
                continue
            g = flows[j]
            if abs(g["first"] - t) > BF_WINDOW:
                continue
            gsrc = (g.get("client") or (None, 0))[0]
            gdst = (g.get("server") or (None, 0))[0]
            if gsrc != src or gdst != dst:
                continue
            if g["dport"] == dport:
                same_port += 1
            sweep.add(g["dport"])
        metas[i][7] = np.log1p(same_port)
        metas[i][8] = min(1.0, len(sweep) / 128.0)


def main():
    malicious = {}
    skip = {"cap_normal.pcap", "cap_real_negative.pcap"}
    for f in sorted(os.listdir(OUT_DIR)):
        if not f.startswith("cap_") or not f.endswith(".pcap") or "bench" in f:
            continue
        if f in skip:
            continue
        path = os.path.join(OUT_DIR, f)
        if os.path.getsize(path) == 0:
            continue
        malicious[f[4:-5]] = path

    normal = [os.path.join(OUT_DIR, f) for f in sorted(os.listdir(OUT_DIR))
              if f.startswith("normal_") and f.endswith(".pcap")]
    normal.append(os.path.join(OUT_DIR, "cap_normal.pcap"))
    # real traffic captured on this machine (authorized local baseline)
    real = os.path.join(OUT_DIR, "real_traffic.pcap")
    if os.path.exists(real):
        normal.append(real)

    flow_recs = []  # (path, flow, tool, origin)
    for tool, path in sorted(malicious.items()):
        for c in extract_flows(path):
            flow_recs.append((path, c, tool, tool))

    bf_sources = {
        "bf_ssh": "bruteforce_ssh",
        "bf_http": "bruteforce_http",
        "scan_syn": "bruteforce_scan",
    }
    for fname, tool in bf_sources.items():
        p = os.path.join(OUT_DIR, fname + ".pcap")
        if not os.path.exists(p):
            continue
        for c in extract_flows(p):
            flow_recs.append((p, c, tool, fname))

    for path in normal:
        for c in extract_flows(path):
            flow_recs.append((path, c, "", os.path.basename(path)))

    flows = [r[1] for r in flow_recs]
    metas = [flow_meta(c) for c in flows]
    cross_flow_meta(flows, metas)

    X_dir, X_sz, X_dt, X_mask, X_meta = [], [], [], [], []
    y, tools, origins = [], [], []
    for (path, c, tool, origin), meta in zip(flow_recs, metas):
        evs = events_of(c)
        X_dir.append([e[0] for e in evs[:MAX_LEN]])
        X_sz.append([size_bucket(e[1]) for e in evs[:MAX_LEN]])
        X_dt.append([dt_bucket(e[2]) for e in evs[:MAX_LEN]])
        X_mask.append([1.0] * min(len(evs), MAX_LEN))
        X_meta.append(meta)
        y.append(1 if tool else 0)
        tools.append(tool)
        origins.append(origin)

    n = len(y)
    arr_dir = np.zeros((n, MAX_LEN), dtype=np.int64)
    arr_sz = np.zeros((n, MAX_LEN), dtype=np.int64)
    arr_dt = np.zeros((n, MAX_LEN), dtype=np.int64)
    arr_mask = np.zeros((n, MAX_LEN), dtype=np.float32)
    for i in range(n):
        ln = len(X_dir[i])
        arr_dir[i, :ln] = X_dir[i]
        arr_sz[i, :ln] = X_sz[i]
        arr_dt[i, :ln] = X_dt[i]
        arr_mask[i, :ln] = X_mask[i]
    arr_meta = np.asarray(X_meta, dtype=np.float32)
    yy = np.asarray(y, dtype=np.int64)

    os.makedirs(DATA_DIR, exist_ok=True)
    torch.save({
        "X_dir": torch.from_numpy(arr_dir),
        "X_sz": torch.from_numpy(arr_sz),
        "X_dt": torch.from_numpy(arr_dt),
        "X_mask": torch.from_numpy(arr_mask),
        "X_meta": torch.from_numpy(arr_meta),
        "y": torch.from_numpy(yy),
        "tools": tools,
        "origins": origins,
        "meta_names": ["is_tls", "has_sni", "duration", "tot_c", "tot_s",
                       "n_events", "dport", "same_port_burst", "ports_sweep"],
        "max_len": MAX_LEN,
    }, os.path.join(DATA_DIR, "dataset.pt"))
    print(f"dataset: {n} flows (malicious={int(yy.sum())}, normal={n - int(yy.sum())}), "
          f"malicious sources={len(malicious) + len(bf_sources)}")
    print(f"saved -> {os.path.join(DATA_DIR, 'dataset.pt')}")


if __name__ == "__main__":
    main()
