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
import bisect
import os
import struct
import sys

import numpy as np
import torch

from tls_fp import ja3_from_clienthello

# Optional feature groups, enabled via env TFLAB_FEATURES=base,group1,group2
FEATURE_GROUPS = [g for g in os.environ.get("TFLAB_FEATURES", "").split(",") if g]
EXCLUDE_PCAPS = set(
    e for e in os.environ.get("TFLAB_EXCLUDE_PCAPS", "").split(",") if e)
HANDSHAKE = "handshake" in FEATURE_GROUPS
HTTPF = "http" in FEATURE_GROUPS
MULTI = "multiscale" in FEATURE_GROUPS
SHAPE = "shape" in FEATURE_GROUPS
JA3F = "ja3" in FEATURE_GROUPS
CIC_MODE = "cic39" in FEATURE_GROUPS or "cicfull" in FEATURE_GROUPS
CIC39 = "cic39" in FEATURE_GROUPS
CICFULL = "cicfull" in FEATURE_GROUPS

META_BASE = 16
META_CIC = 39
SHAPE_N, HTTP_N, JA3_N, HS_N, MS_N, JA3C_N = 5, 7, 2, 5, 11, 1

LAB = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_DIR = os.path.join(LAB, "data", "captures")
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
        ip_tot = struct.unpack("!H", data[off + 2:off + 4])[0]
        if ip_tot == 0:
            ip_tot = len(data) - off
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
        plen = struct.unpack("!H", data[off + 4:off + 6])[0]
        ip_tot = 40 + plen
        ihl = 40
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
        return src, sport, dst, dport, proto, 0, payload, ip_tot, 0, 8, ihl
    if len(data) < l4 + 20:
        return None
    doff = (data[l4 + 12] >> 4) * 4
    if doff < 20 or l4 + doff > len(data):
        return None
    payload = data[l4 + doff:]
    win = struct.unpack("!H", data[l4 + 14:l4 + 16])[0]
    return src, sport, dst, dport, proto, data[l4 + 13], payload, ip_tot, win, doff, ihl


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


def tls13_from_ch(data):
    """True if a ClientHello advertises TLS 1.3 (supported_versions ext)."""
    if len(data) < 5 or data[0] != 1:
        return 0.0
    ml = int.from_bytes(data[1:4], "big")
    b = data[4:4 + ml]
    if len(b) < 38:
        return 0.0
    pos = 2 + 32
    sl = b[pos]
    pos += 1 + sl
    cs = int.from_bytes(b[pos:pos + 2], "big")
    pos += 2 + cs
    cl = b[pos]
    pos += 1 + cl
    if pos + 2 > len(b):
        return 0.0
    ext_total = int.from_bytes(b[pos:pos + 2], "big")
    pos += 2
    end = min(pos + ext_total, len(b))
    while pos + 4 <= end:
        et = int.from_bytes(b[pos:pos + 2], "big")
        el = int.from_bytes(b[pos + 2:pos + 4], "big")
        if pos + 4 + el > end:
            break
        d = b[pos + 4:pos + 4 + el]
        if et == 43 and len(d) >= 2:
            slen = int.from_bytes(d[0:2], "big")
            for i in range(2, min(2 + slen, len(d) - 1)):
                if d[i] == 0x03 and d[i + 1] == 0x04:
                    return 1.0
        pos += 4 + el
    return 0.0


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
        "dport": 0, "proto": 0, "flagcnt": collections.Counter(),
        "synack": 0, "synonly": 0, "rst": 0, "payload_seen": False,
        "c_meta": [], "s_meta": []})
    for ts, data, lt in read_pcap(path):
        pkt = parse_pkt(data, lt)
        if pkt is None:
            continue
        (src, sport, dst, dport, proto, flags, payload,
         pkt_len, win, doff, ihl) = pkt
        key = frozenset(((src, sport), (dst, dport), proto))
        c = conns[key]
        c["proto"] = proto
        if c["first"] is None:
            c["first"] = ts
            c["client"] = (src, sport)
            c["dport"] = dport
        c["last"] = ts
        if proto == 6:
            for name, bit in (("FIN", 0x01), ("SYN", 0x02), ("RST", 0x04),
                              ("PSH", 0x08), ("ACK", 0x10)):
                if flags & bit:
                    c["flagcnt"][name] += 1
            if flags & 0x12 == 0x12:
                c["synack"] += 1
            if flags == 0x02:
                c["synonly"] += 1
            if flags & 0x04:
                c["rst"] += 1
            if payload:
                c["payload_seen"] = True
        if (src, sport) == c["client"]:
            c["c"].append((ts, payload))
            c["c_meta"].append((ts, pkt_len, len(payload), flags, win, doff, ihl))
        else:
            if c["server"] is None:
                c["server"] = (src, sport)
            c["s"].append((ts, payload))
            c["s_meta"].append((ts, pkt_len, len(payload), flags, win, doff, ihl))
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
    tls13 = 0.0
    ch_len = 0.0
    sh_len = 0.0
    max_rec = 0.0
    for _, p in c["c"][:5]:
        max_rec = max(max_rec, float(len(p)))
        if len(p) >= 3 and p[0] == 0x16 and p[1] == 0x03:
            is_tls = 1.0
            if ch_len == 0:
                ch_len = float(len(p))
            if len(p) >= 5:
                rec = p[5:]
                if rec and rec[0] == 1:
                    sni = sni_from_ch(rec)
                    tls13 = tls13_from_ch(rec)
            break
    for _, p in c["s"][:5]:
        max_rec = max(max_rec, float(len(p)))
        if sh_len == 0 and p:
            sh_len = float(len(p))
    dur = max(0.0, (c["last"] or 0) - (c["first"] or 0))
    n_ev = float(sum(1 for _, p in c["c"] if p) + sum(1 for _, p in c["s"] if p))
    return [
        is_tls,
        1.0 if sni else 0.0,
        tls13,
        np.log1p(dur),
        np.log1p(c_bytes), np.log1p(s_bytes),
        np.log1p(n_ev),
        min(1.0, c["dport"] / 65535.0),
        0.0,  # same_port_burst (filled in cross-flow pass)
        0.0,  # ports_sweep (filled in cross-flow pass)
        np.log1p(ch_len),
        np.log1p(sh_len),
        np.log1p(c_bytes) - np.log1p(s_bytes),
        np.log1p(max_rec),
        1.0 if (c_bytes > 0 or s_bytes > 0) else 0.0,
        0.0,  # distinct_dsts_recent (filled in cross-flow pass)
    ]


def cic_features(c):
    """CICFlowMeter-style per-flow aggregate statistics (39 dims)."""
    def stats(vals):
        if not vals:
            return [0.0] * 4
        a = np.asarray(vals, dtype=float)
        return [float(a.min()), float(a.max()), float(a.mean()),
                float(a.std()) if len(a) > 1 else 0.0]

    c_ts = [t for t, p in c["c"]]
    s_ts = [t for t, p in c["s"]]
    c_len = [len(p) for t, p in c["c"]]
    s_len = [len(p) for t, p in c["s"]]
    dur = max(0.0, (c["last"] or 0) - (c["first"] or 0))
    f_iat = [b - a for a, b in zip(c_ts, c_ts[1:]) if b > a]
    b_iat = [b - a for a, b in zip(s_ts, s_ts[1:]) if b > a]
    all_ts = sorted(c_ts + s_ts)
    flow_iat = [b - a for a, b in zip(all_ts, all_ts[1:]) if b > a]
    feats = [dur, len(c_len), len(s_len), sum(c_len), sum(s_len)]
    feats += stats(c_len) + stats(s_len) + stats(f_iat) + stats(b_iat)
    feats += stats(flow_iat)
    fc = c.get("flagcnt") or collections.Counter()
    feats += [float(fc[n]) for n in ("FIN", "SYN", "RST", "PSH", "ACK")]
    down, up = sum(s_len), sum(c_len)
    feats.append(down / up if up > 0 else 0.0)
    active, idle = [], []
    prev = None
    for t in all_ts:
        if prev is not None:
            g = t - prev
            (idle if g > 1.0 else active).append(g)
        prev = t
    feats += stats(active) + stats(idle)
    return feats


CICFULL_NAMES = [
    "flow_duration", "tot_fwd_pkts", "tot_bwd_pkts", "totlen_fwd_pkts",
    "totlen_bwd_pkts", "fwd_pkt_len_max", "fwd_pkt_len_min",
    "fwd_pkt_len_mean", "fwd_pkt_len_std", "bwd_pkt_len_max",
    "bwd_pkt_len_min", "bwd_pkt_len_mean", "bwd_pkt_len_std",
    "flow_byts_s", "flow_pkts_s", "flow_iat_mean", "flow_iat_std",
    "flow_iat_max", "flow_iat_min", "fwd_iat_tot", "fwd_iat_mean",
    "fwd_iat_std", "fwd_iat_max", "fwd_iat_min", "bwd_iat_tot",
    "bwd_iat_mean", "bwd_iat_std", "bwd_iat_max", "bwd_iat_min",
    "fwd_psh_flags", "bwd_psh_flags", "fwd_urg_flags", "bwd_urg_flags",
    "fwd_header_len", "bwd_header_len", "fwd_packets_s", "bwd_packets_s",
    "min_pkt_len", "max_pkt_len", "pkt_len_mean", "pkt_len_std",
    "pkt_len_var", "fin_flag_cnt", "syn_flag_cnt", "rst_flag_cnt",
    "psh_flag_cnt", "ack_flag_cnt", "urg_flag_cnt", "cwe_flag_cnt",
    "ece_flag_cnt", "down_up_ratio", "avg_pkt_size", "avg_fwd_seg_size",
    "avg_bwd_seg_size", "fwd_avg_bytes_bulk", "fwd_avg_packets_bulk",
    "fwd_avg_bulk_rate", "bwd_avg_bytes_bulk", "bwd_avg_packets_bulk",
    "bwd_avg_bulk_rate", "subflow_fwd_pkts", "subflow_fwd_byts",
    "subflow_bwd_pkts", "subflow_bwd_byts", "init_fwd_win_byts",
    "init_bwd_win_byts", "fwd_act_data_pkts", "fwd_seg_size_min",
    "active_min", "active_max", "active_mean", "active_std",
    "idle_min", "idle_max", "idle_mean", "idle_std",
]  # 76 dims, CICFlowMeter-style (bulk rate approximated as 0)


def cic_full_features(c):
    """CICFlowMeter-style full flow statistics (76 dims), using IP total
    lengths, full TCP flag set, window sizes and header lengths."""
    f_ts = [m[0] for m in c["c_meta"]]
    f_len = [m[1] for m in c["c_meta"]]
    f_pl = [m[2] for m in c["c_meta"]]
    f_fl = [m[3] for m in c["c_meta"]]
    f_win = [m[4] for m in c["c_meta"]]
    f_hdr = [m[5] + m[6] for m in c["c_meta"]]
    s_ts = [m[0] for m in c["s_meta"]]
    s_len = [m[1] for m in c["s_meta"]]
    s_pl = [m[2] for m in c["s_meta"]]
    s_fl = [m[3] for m in c["s_meta"]]
    s_win = [m[4] for m in c["s_meta"]]
    s_hdr = [m[5] + m[6] for m in c["s_meta"]]

    def st(vals):
        if not vals:
            return [0.0, 0.0, 0.0, 0.0]
        a = np.asarray(vals, dtype=float)
        return [float(a.min()), float(a.max()), float(a.mean()),
                float(a.std()) if len(a) > 1 else 0.0]

    def iats(ts):
        return [b - a for a, b in zip(ts, ts[1:]) if b > a]

    def flag_cnt(ms, mask):
        return float(sum(1 for m in ms if m[3] & mask))

    dur = max(0.0, (c["last"] or 0) - (c["first"] or 0))
    f_cnt, s_cnt = len(f_len), len(s_len)
    tot_c, tot_s = sum(f_len), sum(s_len)
    all_len = f_len + s_len
    all_ts = sorted(f_ts + s_ts)
    f_iat, b_iat, fl_iat = iats(f_ts), iats(s_ts), iats(all_ts)

    fmin, fmax, fmean, fstd = st(f_len)
    smin, smax, smean, sstd = st(s_len)
    imin, imax, imean, istd = st(fl_iat)
    pmin, pmax, pmean, pstd = st(all_len)

    def iat_stats(vals):
        tot = float(sum(vals))
        mn, mx, me, sd = st(vals)
        return [tot, me, sd, mx, mn]

    fwd_init_win = 0.0
    for i, fl in enumerate(f_fl):
        if fl & 0x02:
            fwd_init_win = float(f_win[i])
            break
    bwd_init_win = 0.0
    for i, fl in enumerate(s_fl):
        if fl & 0x12 == 0x12:
            bwd_init_win = float(s_win[i])
            break

    active, idle = [], []
    prev = None
    for t in all_ts:
        if prev is not None:
            g = t - prev
            (idle if g > 1.0 else active).append(g)
        prev = t

    f = [
        dur, float(f_cnt), float(s_cnt), float(tot_c), float(tot_s),
        fmax, fmin, fmean, fstd, smax, smin, smean, sstd,
        (tot_c + tot_s) / dur if dur > 0 else 0.0,
        (f_cnt + s_cnt) / dur if dur > 0 else 0.0,
        imean, istd, imax, imin,
    ] + iat_stats(f_iat) + iat_stats(b_iat)
    f += [
        flag_cnt(c["c_meta"], 0x08), flag_cnt(c["s_meta"], 0x08),
        flag_cnt(c["c_meta"], 0x20), flag_cnt(c["s_meta"], 0x20),
        float(sum(f_hdr)), float(sum(s_hdr)),
        f_cnt / dur if dur > 0 else 0.0,
        s_cnt / dur if dur > 0 else 0.0,
        pmin, pmax, pmean, pstd, pstd * pstd,
    ]
    f += [flag_cnt(c["c_meta"] + c["s_meta"], m)
          for m in (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x80, 0x40)]
    f += [
        tot_s / tot_c if tot_c > 0 else 0.0,
        pmean,
        float(np.mean(f_pl)) if f_pl else 0.0,
        float(np.mean(s_pl)) if s_pl else 0.0,
        0.0, 0.0, 0.0, 0.0, 0.0, 0.0,  # bulk (approximated)
        float(min(4, f_cnt)), float(sum(f_len[:4])),
        float(min(4, s_cnt)), float(sum(s_len[:4])),
        fwd_init_win, bwd_init_win,
        float(sum(1 for p in f_pl if p > 0)),
        float(min(f_pl)) if f_pl else 0.0,
    ] + st(active) + st(idle)
    return f


def all_meta(c):
    """Fused flow-level vector: behavior features + CIC aggregates + optional
    extra feature groups (cross-flow slots are filled later)."""
    if CIC39:
        return [np.log1p(v) for v in cic_features(c)]
    if CICFULL:
        return [np.log1p(v) for v in cic_full_features(c)]
    feats = flow_meta(c) + [np.log1p(v) for v in cic_features(c)]
    if SHAPE:
        feats += shape_features(c)
    if HTTPF:
        feats += http_features(c)
    if JA3F:
        feats += ja3_features(c)
    if HANDSHAKE:
        feats += [0.0] * HS_N
    if MULTI:
        feats += [0.0] * MS_N
    if JA3F:
        feats += [0.0] * JA3C_N
    return feats


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


def _first_client_hello(c):
    """Return the raw TLS record payload of the first ClientHello (or None)."""
    for _, p in c["c"][:5]:
        if len(p) >= 6 and p[0] == 0x16 and p[1] == 0x03 and p[5] == 1:
            return p
    return None


def _flow_ja3(c):
    p = _first_client_hello(c)
    if p is None:
        return None
    return ja3_from_clienthello(p[5:])


def ja3_features(c):
    """[has_ja3, ja3_bucket] — bucketed so the model cannot memorize exact JA3."""
    j = _flow_ja3(c)
    if not j:
        return [0.0, 0.0]
    return [1.0, 1.0 + (abs(hash(j)) % 127)]


def shape_features(c):
    """Timing / size-shape stats: [iat_cv, log1p(iat_p50), log1p(iat_p90),
    size_cv, size_entropy]."""
    evs = events_of(c)
    iats = [dt for _, _, dt in evs if dt > 0]
    sizes = [sz for _, sz, _ in evs if sz > 0]

    def cv(vals):
        if len(vals) < 2:
            return 0.0
        a = np.asarray(vals, dtype=float)
        m = a.mean()
        return float(a.std() / m) if m > 0 else 0.0

    iat_p50 = float(np.percentile(iats, 50)) if iats else 0.0
    iat_p90 = float(np.percentile(iats, 90)) if iats else 0.0
    ent = 0.0
    if sizes:
        cnt = collections.Counter(size_bucket(s) for s in sizes)
        tot = float(sum(cnt.values()))
        ent = -sum((v / tot) * np.log(v / tot) for v in cnt.values())
    return [cv(iats), np.log1p(iat_p50), np.log1p(iat_p90), cv(sizes), ent]


HTTP_METHODS = (b"GET", b"POST", b"PUT", b"HEAD", b"OPTIONS", b"PATCH", b"DELETE")


def _http_request_info(c):
    for _, p in c["c"]:
        if not p:
            continue
        if not any(p.startswith(m + b" ") for m in HTTP_METHODS):
            continue
        first_line, _, rest = p.partition(b"\r\n")
        method = first_line.split(b" ", 1)[0].decode("latin1", "replace").upper()
        req_len = float(len(first_line))
        headers = []
        conn = None
        for h in rest.split(b"\r\n")[:50]:
            if not h:
                break
            headers.append(h)
            low = h.lower()
            if low.startswith(b"connection:"):
                conn = h.split(b":", 1)[1].strip().lower()
        keep = 1.0 if (conn == b"keep-alive"
                       or (conn is None and b"HTTP/1.1" in first_line)) else 0.0
        return method, req_len, float(len(headers)), keep
    return None, 0.0, 0.0, 0.0


def _http_resp_code(c):
    for _, p in c["s"]:
        if p and p.startswith(b"HTTP/1.") and len(p) >= 12:
            try:
                return float(int(p[9:12])) / 1000.0
            except ValueError:
                return 0.0
    return 0.0


def http_features(c):
    """Shallow non-TLS HTTP features: [is_http, method_get, method_post,
    log1p(req_line_len), log1p(n_headers), keep_alive, resp_code_class]."""
    if _first_client_hello(c) is not None:
        return [0.0] * HTTP_N
    method, req_len, n_headers, keep = _http_request_info(c)
    if method is None:
        return [0.0] * HTTP_N
    return [1.0, float(method == "GET"), float(method == "POST"),
            np.log1p(req_len), np.log1p(n_headers), keep, _http_resp_code(c)]


def extra_layout():
    """Map feature-group names to their starting index in the fused meta
    vector, and return the total meta dimension."""
    idx = META_BASE + META_CIC
    off = {}
    if SHAPE:
        off["shape"] = idx
        idx += SHAPE_N
    if HTTPF:
        off["http"] = idx
        idx += HTTP_N
    if JA3F:
        off["ja3"] = idx
        idx += JA3_N
    if HANDSHAKE:
        off["handshake"] = idx
        idx += HS_N
    if MULTI:
        off["multiscale"] = idx
        idx += MS_N
    if JA3F:
        off["ja3cross"] = idx
        idx += JA3C_N
    return off, idx


def cross_flow_meta(flows, metas):
    """Fill base burst/sweep/distinct-dsts (8/9/15) plus optional feature-group
    cross-flow slots (handshake ratios, multi-scale windows, JA3 stability).
    Flows are grouped by client IP and time-sorted, so each flow only scans its
    own source's 60s neighbourhood instead of the whole flow list."""
    if CIC_MODE:
        return  # pure-CIC modes have no behavior/cross-flow slots
    off, _ = extra_layout()
    by_src = {}
    for i, f in enumerate(flows):
        src = (f.get("client") or (None, 0))[0]
        by_src.setdefault(src, []).append(i)
    for src, idxs in by_src.items():
        idxs.sort(key=lambda fi: flows[fi]["first"])
        ts = [flows[fi]["first"] for fi in idxs]
        for k, i in enumerate(idxs):
            f = flows[i]
            t = f["first"]
            dport = f["dport"]
            dst = (f.get("server") or (None, 0))[0]
            lo = bisect.bisect_left(ts, t - 60.0)
            hi = bisect.bisect_right(ts, t + 60.0)
            same_port = 0
            sweep = set()
            dsts = set()
            src_n = src_est = src_synonly = src_rst = 0
            src_dports = set()
            src_ja3 = {}
            dp_n = dp_est = 0
            b = {1: 0, 5: 0, 10: 0, 60: 0}
            sw = {1: set(), 5: set(), 10: set(), 60: set()}
            dsts_w = {1: set(), 5: set(), 10: set(), 60: set()}
            for m in range(lo, hi):
                if m == k:
                    continue
                g = flows[idxs[m]]
                gsrc = (g.get("client") or (None, 0))[0]
                gdst = (g.get("server") or (None, 0))[0]
                dtg = abs(g["first"] - t)
                if dtg > 60.0:
                    continue
                for w in (1, 5, 10, 60):
                    if dtg <= w:
                        dsts_w[w].add(gdst)
                if gdst == dst:
                    for w in (1, 5, 10, 60):
                        if dtg <= w:
                            sw[w].add(g["dport"])
                            if g["dport"] == dport:
                                b[w] += 1
                if dtg <= BF_WINDOW:
                    dsts.add(gdst)
                    est = bool(g["payload_seen"]) or g["synack"] > 0
                    src_n += 1
                    if est:
                        src_est += 1
                    if g["synonly"] > 0:
                        src_synonly += 1
                    if g["rst"] > 0 and not est:
                        src_rst += 1
                    src_dports.add(g["dport"])
                    if g["dport"] == dport:
                        dp_n += 1
                        if est:
                            dp_est += 1
                    if JA3F:
                        jj = _flow_ja3(g)
                        if jj:
                            src_ja3[jj] = src_ja3.get(jj, 0) + 1
            metas[i][8] = np.log1p(b[10])
            metas[i][9] = min(1.0, len(sw[10]) / 128.0)
            metas[i][15] = min(1.0, len(dsts_w[10]) / 64.0)
            if HANDSHAKE:
                s = off["handshake"]
                metas[i][s] = src_est / src_n if src_n else 0.0
                metas[i][s + 1] = src_synonly / src_n if src_n else 0.0
                metas[i][s + 2] = src_rst / src_n if src_n else 0.0
                metas[i][s + 3] = np.log1p(src_n)
                metas[i][s + 4] = dp_est / dp_n if dp_n else 0.0
            if MULTI:
                s = off["multiscale"]
                kk = 0
                for w in (1, 5, 60):
                    metas[i][s + kk] = np.log1p(b[w])
                    metas[i][s + kk + 1] = min(1.0, len(sw[w]) / 128.0)
                    metas[i][s + kk + 2] = min(1.0, len(dsts_w[w]) / 64.0)
                    kk += 3
                metas[i][s + 9] = np.log1p(len(src_dports))
                metas[i][s + 10] = src_rst / src_n if src_n else 0.0
            if JA3F:
                s = off["ja3cross"]
                my = _flow_ja3(f)
                stab = 0.0
                if my and src_ja3:
                    tot = sum(src_ja3.values())
                    stab = src_ja3.get(my, 0) / tot if tot else 0.0
                metas[i][s] = stab


def main():
    malicious = {}
    skip = {"cap_normal.pcap", "cap_real_negative.pcap"}

    def add_mal(path, tool=None):
        base = os.path.basename(path)
        if base in skip or "bench" in base or base in EXCLUDE_PCAPS:
            return
        if os.path.getsize(path) == 0:
            return
        if tool is None:
            if not base.startswith("cap_") or not base.endswith(".pcap"):
                return
            tool = base[4:-5]
        elif not base.endswith(".pcap"):
            return
        malicious.setdefault(tool, []).append(path)

    for f in sorted(os.listdir(OUT_DIR)):
        add_mal(os.path.join(OUT_DIR, f))
    # parameterized reruns: data/captures/rounds/<tool>/cap_r*.pcap
    rounds_dir = os.path.join(OUT_DIR, "rounds")
    if os.path.isdir(rounds_dir):
        for tool in sorted(os.listdir(rounds_dir)):
            td = os.path.join(rounds_dir, tool)
            if not os.path.isdir(td):
                continue
            for f in sorted(os.listdir(td)):
                add_mal(os.path.join(td, f), tool=tool)

    normal = [os.path.join(OUT_DIR, f) for f in sorted(os.listdir(OUT_DIR))
              if f.startswith("normal_") and f.endswith(".pcap")
              and f not in EXCLUDE_PCAPS]
    normal.append(os.path.join(OUT_DIR, "cap_normal.pcap"))
    # real traffic captured on this machine (authorized local baseline)
    real = os.path.join(OUT_DIR, "real_traffic.pcap")
    if os.path.exists(real) and os.path.basename(real) not in EXCLUDE_PCAPS:
        normal.append(real)
    for extra in ("real_traffic2.pcap", "real_traffic3.pcap", "real_traffic4.pcap",
                  "real_traffic5.pcap", "real_traffic_sr.pcap"):
        p = os.path.join(OUT_DIR, extra)
        if os.path.exists(p) and extra not in EXCLUDE_PCAPS:
            normal.append(p)

    flow_recs = []  # (path, flow, tool, origin)
    for tool, paths in sorted(malicious.items()):
        for path in paths:
            for c in extract_flows(path):
                flow_recs.append((path, c, tool, os.path.basename(path)))

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
    metas = [all_meta(c) for c in flows]
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
    cic_n = ["duration", "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes",
             "fwd_len_min", "fwd_len_max", "fwd_len_mean", "fwd_len_std",
             "bwd_len_min", "bwd_len_max", "bwd_len_mean", "bwd_len_std",
             "fwd_iat_min", "fwd_iat_max", "fwd_iat_mean", "fwd_iat_std",
             "bwd_iat_min", "bwd_iat_max", "bwd_iat_mean", "bwd_iat_std",
             "flow_iat_min", "flow_iat_max", "flow_iat_mean", "flow_iat_std",
             "fin_cnt", "syn_cnt", "rst_cnt", "psh_cnt", "ack_cnt",
             "down_up_ratio", "active_min", "active_max", "active_mean",
             "active_std", "idle_min", "idle_max", "idle_mean", "idle_std"]
    if CIC39:
        meta_n = ["cic_" + n for n in cic_n]
    elif CICFULL:
        meta_n = ["cicf_" + n for n in CICFULL_NAMES]
    else:
        meta_n = (["is_tls", "has_sni", "tls13", "duration", "tot_c", "tot_s",
                   "n_events", "dport", "same_port_burst", "ports_sweep",
                   "ch_len", "sh_len", "req_resp_ratio", "max_rec", "estab",
                   "distinct_dsts"]
                  + ["cic_" + n for n in cic_n])
    if SHAPE:
        meta_n += ["iat_cv", "iat_p50", "iat_p90", "size_cv", "size_entropy"]
    if HTTPF:
        meta_n += ["is_http", "method_get", "method_post", "req_line_len",
                   "n_headers", "keep_alive", "resp_code_class"]
    if JA3F:
        meta_n += ["has_ja3", "ja3_bucket"]
    if HANDSHAKE:
        meta_n += ["est_ratio_src", "synonly_ratio_src", "rst_ratio_src",
                   "src_conns", "est_ratio_dport"]
    if MULTI:
        meta_n += ["burst_1s", "sweep_1s", "dsts_1s",
                   "burst_5s", "sweep_5s", "dsts_5s",
                   "burst_60s", "sweep_60s", "dsts_60s",
                   "src_uniq_dports", "src_failed_ratio"]
    if JA3F:
        meta_n += ["ja3_stability"]

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
        "meta_names": meta_n,
        "max_len": MAX_LEN,
    }, os.path.join(DATA_DIR, "dataset.pt"))
    print(f"dataset: {n} flows (malicious={int(yy.sum())}, normal={n - int(yy.sum())}), "
          f"malicious sources={len(malicious) + len(bf_sources)}")
    print(f"saved -> {os.path.join(DATA_DIR, 'dataset.pt')}")


if __name__ == "__main__":
    main()
