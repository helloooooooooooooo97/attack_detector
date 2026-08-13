#!/usr/bin/env python3
"""CIC-flow-feature baseline (self-contained comparison experiment).

Reproduces the TFLab evaluation (A random split, B tool-level 5-fold CV,
real-traffic FPR) but feeds the model ONLY CICFlowMeter-style aggregate
statistics -- no event sequence, no cross-flow context. Does not modify or
import anything from the production pipeline (own pcap parser + features).

Usage: python3 ml/cic_baseline.py
"""

import collections
import os
import struct
import sys
import time

import numpy as np
import torch
import torch.nn as nn
from sklearn.preprocessing import StandardScaler

LAB = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(LAB, "out")


# ---------------- own pcap parsing (self-contained) ----------------

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
        return src, sport, dst, dport, proto, 0, data[l4 + 8:l4 + ul]
    if len(data) < l4 + 20:
        return None
    doff = (data[l4 + 12] >> 4) * 4
    if doff < 20 or l4 + doff > len(data):
        return None
    return src, sport, dst, dport, proto, data[l4 + 13], data[l4 + doff:]


def extract_flows(path):
    conns = collections.defaultdict(lambda: {
        "c": [], "s": [], "first": None, "last": None, "client": None,
        "server": None, "dport": 0, "flags": collections.Counter()})
    for ts, data, lt in read_pcap(path):
        pkt = parse_pkt(data, lt)
        if pkt is None:
            continue
        src, sport, dst, dport, proto, flags, payload = pkt
        key = frozenset(((src, sport), (dst, dport), proto))
        c = conns[key]
        if c["first"] is None:
            c["first"] = ts
            c["client"] = (src, sport)
            c["dport"] = dport
        c["last"] = ts
        if proto == 6:
            for name, bit in (("FIN", 0x01), ("SYN", 0x02), ("RST", 0x04),
                              ("PSH", 0x08), ("ACK", 0x10)):
                if flags & bit:
                    c["flags"][name] += 1
        if (src, sport) == c["client"]:
            c["c"].append((ts, payload))
        else:
            if c["server"] is None:
                c["server"] = (src, sport)
            c["s"].append((ts, payload))
    return [c for c in conns.values() if c["c"] or c["s"]]


# ---------------- CIC-style features ----------------

def stats(vals):
    if not vals:
        return [0.0] * 4
    a = np.asarray(vals, dtype=float)
    return [float(a.min()), float(a.max()), float(a.mean()),
            float(a.std()) if len(a) > 1 else 0.0]


def cic_features(c):
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
    fc = c["flags"]
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


def build_dataset():
    """Enumerate the same pcaps as the production pipeline; return
    X_cic, y, tools, origins."""
    skip = {"cap_normal.pcap", "cap_real_negative.pcap"}
    paths = []
    for f in sorted(os.listdir(OUT)):
        if not f.startswith("cap_") or not f.endswith(".pcap") or "bench" in f:
            continue
        if f in skip or os.path.getsize(os.path.join(OUT, f)) == 0:
            continue
        paths.append((os.path.join(OUT, f), f[4:-5], f[4:-5]))
    for f in sorted(os.listdir(OUT)):
        if f.startswith("normal_") and f.endswith(".pcap"):
            paths.append((os.path.join(OUT, f), "", f))
    for fname, tool in (("bf_ssh", "bruteforce_ssh"),
                        ("bf_http", "bruteforce_http"),
                        ("scan_syn", "bruteforce_scan")):
        p = os.path.join(OUT, fname + ".pcap")
        if os.path.exists(p):
            paths.append((p, tool, fname))
    for name in ("cap_normal.pcap", "real_traffic.pcap", "real_traffic2.pcap",
                 "real_traffic3.pcap", "real_traffic4.pcap"):
        p = os.path.join(OUT, name)
        if os.path.exists(p):
            paths.append((p, "", name))
    X, y, tools, origins = [], [], [], []
    for path, tool, origin in paths:
        for c in extract_flows(path):
            X.append(cic_features(c))
            y.append(1 if tool else 0)
            tools.append(tool)
            origins.append(origin)
    return (np.asarray(X, dtype=np.float32), np.asarray(y, dtype=np.int64),
            tools, origins)


# ---------------- model + evaluation ----------------

class MLP(nn.Module):
    def __init__(self, n_in, hidden=128):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(n_in, hidden), nn.ReLU(), nn.Dropout(0.2),
            nn.Linear(hidden, hidden), nn.ReLU(), nn.Dropout(0.2),
            nn.Linear(hidden, 1))

    def forward(self, x):
        return self.net(x).squeeze(-1)


def train_mlp(Xtr, ytr, Xva, yva, epochs=30, bs=256):
    torch.manual_seed(0)
    model = MLP(Xtr.shape[1])
    opt = torch.optim.AdamW(model.parameters(), lr=1e-3, weight_decay=1e-4)
    lossf = nn.BCEWithLogitsLoss()
    Xtr = torch.as_tensor(Xtr, dtype=torch.float32)
    ytr = torch.as_tensor(ytr, dtype=torch.float32) * 0.9 + 0.05
    Xva = torch.as_tensor(Xva, dtype=torch.float32)
    yva = torch.as_tensor(yva, dtype=torch.float32)
    best, patience, best_state = 1e9, 0, None
    n = len(ytr)
    for epoch in range(epochs):
        model.train()
        perm = torch.randperm(n)
        for i in range(0, n, bs):
            idx = perm[i:i + bs]
            opt.zero_grad()
            loss = lossf(model(Xtr[idx]), ytr[idx])
            loss.backward()
            opt.step()
        model.eval()
        with torch.no_grad():
            vloss = lossf(model(Xva), yva).item()
        if vloss < best * (1 - 1e-3):
            best, patience = vloss, 0
            best_state = {k: v.detach().clone() for k, v in model.state_dict().items()}
        else:
            patience += 1
            if patience >= 5:
                break
    model.load_state_dict(best_state)
    return model


def metrics(y, p):
    pred = (p >= 0.5).astype(int)
    tp = int(((pred == 1) & (y == 1)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    tn = int(((pred == 0) & (y == 0)).sum())
    rec = tp / (tp + fn) if tp + fn else 0.0
    prec = tp / (tp + fp) if tp + fp else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    order = np.argsort(p)
    y_s = y[order][::-1]
    tpr = np.cumsum(y_s) / max(1, y_s.sum())
    fpr = np.cumsum(1 - y_s) / max(1, (1 - y_s).sum())
    auroc = float(np.trapezoid(tpr, fpr)) if len(tpr) > 1 else float("nan")
    return {"recall": rec, "precision": prec, "f1": f1,
            "specificity": tn / (tn + fp) if tn + fp else 0.0,
            "auroc": auroc, "n": len(y)}


def main():
    t0 = time.time()
    X, y, tools, origins = build_dataset()
    print(f"CIC 特征: {X.shape[1]} 维 | 流数 {len(y)} "
          f"(恶意 {int(y.sum())} / 正常 {len(y)-int(y.sum())}) | 构建 {time.time()-t0:.0f}s")

    rng = np.random.RandomState(42)
    # ---- A. random split (same scheme/seed as production) ----
    idx = np.arange(len(y))
    pos, neg = idx[y == 1].copy(), idx[y == 0].copy()
    rng.shuffle(pos); rng.shuffle(neg)
    kp, kn = int(len(pos) * 0.7), int(len(neg) * 0.7)
    trp, restp = pos[:kp], pos[kp:]
    trn, restn = neg[:kn], neg[kn:]
    valp, tep = restp[:len(restp)//2], restp[len(restp)//2:]
    valn, ten = restn[:len(restn)//2], restn[len(restn)//2:]
    tr_idx = np.concatenate([trp, trn])
    va_idx = np.concatenate([valp, valn])
    te_idx = np.concatenate([tep, ten])
    sc = StandardScaler().fit(X[tr_idx])
    model = train_mlp(sc.transform(X[tr_idx]), y[tr_idx],
                      sc.transform(X[va_idx]), y[va_idx])
    with torch.no_grad():
        p = torch.sigmoid(torch.as_tensor(
            model(torch.as_tensor(sc.transform(X[te_idx]), dtype=torch.float32)))).numpy()
    m = metrics(y[te_idx], p)
    print("\n=== A. 随机分割（CIC 特征） ===")
    print(f"recall={m['recall']:.3f} precision={m['precision']:.3f} "
          f"F1={m['f1']:.3f} AUROC={m['auroc']:.3f} specificity={m['specificity']:.3f}")

    # ---- B. tool-level 5-fold CV ----
    print("\n=== B. 工具级 5 折交叉验证（CIC 特征） ===")
    rng2 = np.random.RandomState(42)
    tl = sorted({t for t in tools if t})
    rng2.shuffle(tl)
    folds = [set(tl[i::5]) for i in range(5)]
    nidx = np.array([i for i, t in enumerate(tools) if not t])
    rng2.shuffle(nidx)
    kn = int(len(nidx) * 0.7); kn2 = int(len(nidx) * 0.85)
    agg = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    aucs = []
    for fi, held in enumerate(folds):
        tr = [i for i, t in enumerate(tools) if t and t not in held]
        r = np.random.RandomState(fi)
        r.shuffle(tr)
        kt = int(len(tr) * 0.85)
        train = np.array(tr[:kt] + list(nidx[:kn]))
        val = np.array(tr[kt:] + list(nidx[kn:kn2]))
        test = np.array([i for i, t in enumerate(tools) if t in held] + list(nidx[kn2:]))
        scf = StandardScaler().fit(X[train])
        mf = train_mlp(scf.transform(X[train]), y[train],
                       scf.transform(X[val]), y[val])
        with torch.no_grad():
            pf = torch.sigmoid(torch.as_tensor(
                mf(torch.as_tensor(scf.transform(X[test]), dtype=torch.float32)))).numpy()
        pred = (pf >= 0.5).astype(int)
        yy = y[test]
        agg["tp"] += int(((pred == 1) & (yy == 1)).sum())
        agg["fp"] += int(((pred == 1) & (yy == 0)).sum())
        agg["fn"] += int(((pred == 0) & (yy == 1)).sum())
        agg["tn"] += int(((pred == 0) & (yy == 0)).sum())
        mf2 = metrics(yy, pf)
        if not np.isnan(mf2["auroc"]):
            aucs.append(mf2["auroc"])
    tp, fp, fn, tn = agg.values()
    rec = tp / (tp + fn) if tp + fn else 0.0
    prec = tp / (tp + fp) if tp + fp else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    print(f"recall={rec:.3f} precision={prec:.3f} F1={f1:.3f} "
          f"AUROC={np.mean(aucs):.3f} specificity={tn/(tn+fp) if tn+fp else 0:.3f}")

    # ---- real-traffic FPR (train on all, predict the 4 real captures) ----
    print("\n=== 真实流量误报（CIC 特征，全量训练后预测） ===")
    sc_all = StandardScaler().fit(X)
    model_all = train_mlp(sc_all.transform(X), y,
                          sc_all.transform(X[va_idx]), y[va_idx])
    tot_fp = tot_n = 0
    for name in ("real_traffic.pcap", "real_traffic2.pcap",
                 "real_traffic3.pcap", "real_traffic4.pcap"):
        pth = os.path.join(OUT, name)
        if not os.path.exists(pth):
            continue
        Xr = np.asarray([cic_features(c) for c in extract_flows(pth)], dtype=np.float32)
        with torch.no_grad():
            pr = torch.sigmoid(torch.as_tensor(
                model_all(torch.as_tensor(sc_all.transform(Xr), dtype=torch.float32)))).numpy()
        fp = int((pr >= 0.5).sum())
        tot_fp += fp; tot_n += len(pr)
        print(f"  {name}: {fp}/{len(pr)} ({100*fp/len(pr):.2f}%)")
    print(f"  合计: {tot_fp}/{tot_n} ({100*tot_fp/tot_n:.2f}%)")

    # ---- C. brute-force / port-scan (same scheme as production split_bf) ----
    print("\n=== C. 爆破/扫描检测（CIC 特征） ===")
    cases = [
        ("C1 同分布留出 30%", (), 0.3),
        ("C2 跨模式: 未见 SYN 扫描", ("scan_syn",), 0.0),
        ("C3 跨模式: 未见 SSH 爆破", ("bf_ssh",), 0.0),
        ("C4 跨模式: 未见 HTTP 爆破", ("bf_http",), 0.0),
    ]
    for label, held_bf, frac in cases:
        rngc = np.random.RandomState(11)
        tools_idx = [i for i, t in enumerate(tools)
                     if t and not t.startswith("bruteforce")]
        bf_idx = [i for i, t in enumerate(tools) if t.startswith("bruteforce")]
        norm_idx = [i for i, t in enumerate(tools) if not t]
        held = [i for i in bf_idx if origins[i] in held_bf]
        rest = [i for i in bf_idx if origins[i] not in held_bf]
        rngc.shuffle(rest); rngc.shuffle(norm_idx); rngc.shuffle(tools_idx)
        kb = int(len(rest) * (1 - frac))
        kn = int(len(norm_idx) * 0.7); kn2 = int(len(norm_idx) * 0.85)
        kt = int(len(tools_idx) * 0.85)
        kbv = kb + max(1, int(len(rest) * 0.1))
        train = np.array(tools_idx[:kt] + rest[:kb] + norm_idx[:kn])
        val = np.array(tools_idx[kt:] + rest[kb:kbv] + norm_idx[kn:kn2])
        test = np.array(held + rest[kbv:] + norm_idx[kn2:])
        scc = StandardScaler().fit(X[train])
        mc = train_mlp(scc.transform(X[train]), y[train],
                       scc.transform(X[val]), y[val])
        with torch.no_grad():
            pc = torch.sigmoid(torch.as_tensor(
                mc(torch.as_tensor(scc.transform(X[test]), dtype=torch.float32)))).numpy()
        mc_ = metrics(y[test], pc)
        yy = y[test]; pred = (pc >= 0.5).astype(int)
        rec_scan = rec_ssh = rec_http = None
        for src_name, key in (("bruteforce_scan", "scan_syn"),
                              ("bruteforce_ssh", "bf_ssh"),
                              ("bruteforce_http", "bf_http")):
            sel = [j for j, i in enumerate(test)
                   if tools[i] == src_name or origins[i] == key]
            if sel:
                n = len(sel)
                tp = int((pred[sel] == 1).sum())
                r = tp / n if n else 0.0
                if src_name == "bruteforce_scan":
                    rec_scan = r
                elif src_name == "bruteforce_ssh":
                    rec_ssh = r
                else:
                    rec_http = r
        fpr = int((pred[yy == 0] == 1).sum()) / max(1, int((yy == 0).sum()))
        print(f"  {label}: recall={mc_['recall']:.3f} AUROC={mc_['auroc']:.3f} "
              f"正常FPR={fpr:.3f}"
              + (f" | scan={rec_scan:.2f}" if rec_scan is not None else "")
              + (f" ssh={rec_ssh:.2f}" if rec_ssh is not None else "")
              + (f" http={rec_http:.2f}" if rec_http is not None else ""))

    print("\n=== 对比参考（TFLab 事件序列 + 行为特征） ===")
    print("  A 随机: recall=0.990 AUROC=0.999 specificity=0.997")
    print("  B 工具5折: recall=0.236 AUROC=0.804")
    print("  真实流量误报: 0.75% (11/1471)")
    print("  C1 同分布爆破: recall=1.000 | C2 未见SYN扫描: 1.000(最佳配置)")
    print("  C3 未见SSH爆破: 0.000(0.5阈值) | C4 未见HTTP爆破: 1.000")


if __name__ == "__main__":
    main()
