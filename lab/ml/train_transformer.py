#!/usr/bin/env python3
"""Train a small Transformer flow classifier and report recall.

Dataset: ml/data/dataset.pt (flow event sequences + flow meta).

Two evaluations:
  A. random flow split (in-distribution)
  B. scenario split: hold out a subset of tools entirely (unseen-tool recall)

Outputs metrics + per-tool recall tables and saves the model.
"""

import json
import math
import os
import sys

import numpy as np
import torch
import torch.nn as nn
from sklearn.metrics import (auc, confusion_matrix, precision_recall_curve,
                             roc_auc_score, roc_curve)

DEVICE = "cpu"  # MPS lacks transformer padding-mask fast path; dataset is small
DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "dataset.pt")
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")


class FlowTransformer(nn.Module):
    def __init__(self, d_model=64, nhead=4, layers=2, ff=128, meta_dim=9,
                 max_len=96, dropout=0.1):
        super().__init__()
        self.dir_emb = nn.Embedding(2, d_model)
        self.sz_emb = nn.Embedding(32, d_model)
        self.dt_emb = nn.Embedding(12, d_model)
        self.pos = nn.Parameter(torch.randn(1, max_len + 1, d_model) * 0.02)
        self.cls = nn.Parameter(torch.randn(d_model) * 0.02)
        self.meta_proj = nn.Linear(meta_dim, d_model)
        enc = nn.TransformerEncoderLayer(
            d_model=d_model, nhead=nhead, dim_feedforward=ff,
            dropout=dropout, batch_first=True, activation="gelu")
        self.enc = nn.TransformerEncoder(enc, num_layers=layers)
        self.head = nn.Sequential(
            nn.LayerNorm(d_model), nn.Dropout(dropout), nn.Linear(d_model, 1))

    def forward(self, X_dir, X_sz, X_dt, X_mask, X_meta):
        B, L = X_dir.shape
        ev = self.dir_emb(X_dir) + self.sz_emb(X_sz) + self.dt_emb(X_dt)
        cls = self.cls.unsqueeze(0).expand(B, -1) + self.meta_proj(X_meta)
        seq = torch.cat([cls.unsqueeze(1), ev], dim=1)
        seq = seq + self.pos[:, :L + 1]
        pad = torch.cat([torch.zeros(B, 1, device=X_mask.device), X_mask], dim=1)
        out = self.enc(seq, src_key_padding_mask=pad.bool())
        return self.head(out[:, 0]).squeeze(-1)


def metrics(y, logit, threshold=0.5):
    p = torch.sigmoid(torch.as_tensor(logit)).numpy()
    pred = (p >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred).ravel()
    recall = tp / (tp + fn) if tp + fn else 0.0
    precision = tp / (tp + fp) if tp + fp else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    try:
        auroc = roc_auc_score(y, p)
    except ValueError:
        auroc = float("nan")
    pr, rc, _ = precision_recall_curve(y, p)
    auprc = auc(rc, pr)
    return {
        "recall": recall, "precision": precision, "f1": f1,
        "auroc": auroc, "auprc": auprc,
        "specificity": tn / (tn + fp) if tn + fp else 0.0,
        "n": len(y), "tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn),
    }


def train_model(tr, va):
    torch.manual_seed(0)
    model = FlowTransformer().to(DEVICE)
    opt = torch.optim.AdamW(model.parameters(), lr=1e-3, weight_decay=1e-4)
    sched = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=40)
    lossf = nn.BCEWithLogitsLoss()

    def batch(t):
        return {k: t[k].to(DEVICE) for k in ("X_dir", "X_sz", "X_dt", "X_mask", "X_meta")}

    best, patience, best_state = 1e9, 0, None
    for epoch in range(40):
        model.train()
        perm = torch.randperm(len(tr["y"]))
        tl = 0.0
        for i in range(0, len(perm), 64):
            idx = perm[i:i + 64]
            b = batch({k: v[idx] for k, v in tr.items() if k.startswith("X")})
            yb = tr["y"][idx].float().to(DEVICE)
            yb = yb * 0.9 + 0.05  # label smoothing, prevents logit saturation
            opt.zero_grad()
            out = model(**b)
            loss = lossf(out, yb)
            loss.backward()
            opt.step()
            tl += loss.item() * len(idx)
        sched.step()
        model.eval()
        with torch.no_grad():
            vb = batch({k: v for k, v in va.items() if k.startswith("X")})
            vout = model(**vb).cpu()
            vloss = lossf(vout, va["y"].float()).item()
        if vloss < best - 1e-4:
            best, patience = vloss, 0
            best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
        else:
            patience += 1
            if patience >= 6:
                break
    model.load_state_dict(best_state)
    return model


def eval_split(model, X, y, threshold=0.5):
    model.eval()
    with torch.no_grad():
        Xf = {k: v.to(DEVICE) for k, v in X.items() if k.startswith("X")}
        out = model(**Xf).cpu()
    return metrics(y.numpy(), out.numpy(), threshold=threshold)


def tune_threshold(model, X, y):
    """Youden-optimal threshold on the validation set (max tpr - fpr)."""
    model.eval()
    with torch.no_grad():
        Xf = {k: v.to(DEVICE) for k, v in X.items() if k.startswith("X")}
        logit = model(**Xf).cpu().numpy()
    p = 1 / (1 + np.exp(-logit))
    fpr, tpr, ths = roc_curve(y.numpy(), p)
    j = tpr - fpr
    return ths[int(np.argmax(j))]


def per_tool_recall(model, X, y, tools, threshold=0.5):
    """Recall per malicious tool + FP per normal source, on a test set."""
    model.eval()
    with torch.no_grad():
        Xf = {k: v.to(DEVICE) for k, v in X.items() if k.startswith("X")}
        logit = model(**Xf).cpu().numpy()
    p = 1 / (1 + np.exp(-logit))
    pred = (p >= threshold).astype(int)
    rows = {}
    for t, yy, pp in zip(tools, y.numpy(), pred):
        if t:
            r = rows.setdefault(t, {"n": 0, "tp": 0})
            r["n"] += 1
            r["tp"] += int(pp == 1 and yy == 1)
        else:
            r = rows.setdefault("__normal__", {"n": 0, "fp": 0})
            r["n"] += 1
            r["fp"] += int(pp == 1 and yy == 0)
    out = []
    for t, r in sorted(rows.items()):
        if t == "__normal__":
            out.append({"tool": "normal", "recall": 1 - r["fp"] / r["n"] if r["n"] else 0,
                        "n": r["n"], "fp": r["fp"]})
        else:
            out.append({"tool": t, "recall": r["tp"] / r["n"] if r["n"] else 0,
                        "n": r["n"], "tp": r["tp"]})
    return out


def split_random(d):
    idx = np.arange(len(d["y"]))
    rng = np.random.RandomState(42)
    pos = idx[d["y"].numpy() == 1]
    neg = idx[d["y"].numpy() == 0]
    def part(a, frac):
        rng.shuffle(a)
        k = int(len(a) * frac)
        return a[:k], a[k:]
    trp, restp = part(pos.copy(), 0.7)
    trn, restn = part(neg.copy(), 0.7)
    valp, tep = part(restp.copy(), 0.5)
    valn, ten = part(restn.copy(), 0.5)
    def sub(idx):
        return {k: v[torch.from_numpy(idx)] for k, v in d.items()
                if k in ("X_dir", "X_sz", "X_dt", "X_mask", "X_meta", "y")}
    return sub(np.concatenate([trp, trn])), sub(np.concatenate([valp, valn])), \
        sub(np.concatenate([tep, ten])), np.concatenate([tep, ten])


def split_scenario(d, holdout_frac=0.2):
    """Hold out a fraction of malicious tools entirely; normals split 70/15/15."""
    tools = sorted({t for t in d["tools"] if t})
    step = max(1, round(1 / holdout_frac))
    held = set(tools[::step])
    rng = np.random.RandomState(7)
    mal = [i for i, t in enumerate(d["tools"]) if t and t not in held]
    norm = [i for i, t in enumerate(d["tools"]) if not t]
    rng.shuffle(mal)
    rng.shuffle(norm)
    km = int(len(mal) * 0.8)
    kn = int(len(norm) * 0.7)
    km2 = int(len(mal) * 0.95)
    kn2 = int(len(norm) * 0.85)
    train = mal[:km] + norm[:kn]
    val = mal[km:km2] + norm[kn:kn2]
    test = [i for i, t in enumerate(d["tools"]) if t in held] + norm[kn2:]
    def sub(idx):
        return {k: v[torch.from_numpy(np.asarray(idx))] for k, v in d.items()
                if k in ("X_dir", "X_sz", "X_dt", "X_mask", "X_meta", "y")}
    return sub(train), sub(val), sub(test), test, sorted(held)


def split_bf(d, held_bf=(), bf_test_frac=0.3):
    """Brute-force evaluation split.

    held_bf      : origins (bf_ssh/bf_http/scan_syn) kept ENTIRELY in test
    bf_test_frac : fraction of the remaining bf flows also held out (in-dist)
    """
    rng = np.random.RandomState(11)
    tools_idx = [i for i, t in enumerate(d["tools"]) if t and not t.startswith("bruteforce")]
    bf_idx = [i for i, t in enumerate(d["tools"]) if t.startswith("bruteforce")]
    norm_idx = [i for i, t in enumerate(d["tools"]) if not t]
    held = [i for i in bf_idx if d["origins"][i] in held_bf]
    rest = [i for i in bf_idx if d["origins"][i] not in held_bf]
    rng.shuffle(rest)
    rng.shuffle(norm_idx)
    rng.shuffle(tools_idx)
    kb = int(len(rest) * (1 - bf_test_frac))
    kn = int(len(norm_idx) * 0.7)
    kn2 = int(len(norm_idx) * 0.85)
    kt = int(len(tools_idx) * 0.85)
    kbv = kb + max(1, int(len(rest) * 0.1))
    train = tools_idx[:kt] + rest[:kb] + norm_idx[:kn]
    val = tools_idx[kt:] + rest[kb:kbv] + norm_idx[kn:kn2]
    test = held + rest[kbv:] + norm_idx[kn2:]
    def sub(idx):
        return {k: v[torch.from_numpy(np.asarray(idx))] for k, v in d.items()
                if k in ("X_dir", "X_sz", "X_dt", "X_mask", "X_meta", "y")}
    return sub(train), sub(val), sub(test), test


def bf_report(model, te, te_idx, d, label):
    m = eval_split(model, te, te["y"])
    print(f"\n--- {label} ---")
    print(f"recall={m['recall']:.3f} precision={m['precision']:.3f} F1={m['f1']:.3f} "
          f"AUROC={m['auroc']:.3f} specificity={m['specificity']:.3f} (n={m['n']})")
    rows = per_tool_recall(model, te, te["y"],
                           [d["tools"][i] for i in te_idx], threshold=0.5)
    for r in rows:
        tag = r["tool"]
        if tag.startswith("bruteforce"):
            print(f"  {tag:18s} recall={r['recall']:.3f} (n={r['n']}, tp={r.get('tp', 0)})")
        elif tag == "normal":
            print(f"  normal: FPR={1-r['recall']:.4f} (n={r['n']}, fp={r['fp']})")
    return m


def main():
    d = torch.load(DATA, weights_only=False)
    for k in ("X_dir", "X_sz", "X_dt", "X_mask", "X_meta"):
        d[k] = d[k].float() if k in ("X_mask", "X_meta") else d[k].long()

    os.makedirs(OUT, exist_ok=True)
    report = {"dataset": {"n": len(d["y"]),
                          "malicious": int(d["y"].sum()),
                          "normal": len(d["y"]) - int(d["y"].sum())}}

    # ---- A. random split ----
    tr, va, te, te_idx = split_random(d)
    model = train_model(tr, va)
    torch.save(model.state_dict(), os.path.join(OUT, "flow_transformer.pt"))
    th = tune_threshold(model, va, va["y"])
    m = eval_split(model, te, te["y"], threshold=th)
    th0 = 0.5
    m0 = eval_split(model, te, te["y"], threshold=th0)
    report["random_split"] = {"fixed_0.5": m0, "tuned": m}
    print("=== A. 随机分割 (in-distribution) ===")
    print(f"固定阈值0.5: recall={m0['recall']:.3f} precision={m0['precision']:.3f} "
          f"F1={m0['f1']:.3f} specificity={m0['specificity']:.3f}")
    print(f"recall={m['recall']:.3f} precision={m['precision']:.3f} "
          f"F1={m['f1']:.3f} AUROC={m['auroc']:.3f} AUPRC={m['auprc']:.3f} "
          f"specificity={m['specificity']:.3f}  (n={m['n']}, th={th:.2f})")
    rows = per_tool_recall(model, te, te["y"],
                           [d["tools"][i] for i in te_idx], threshold=th)
    report["random_split_per_tool"] = rows
    low = [r for r in rows if r["tool"] != "normal" and r["recall"] < 0.8]
    print(f"per-tool recall: {len([r for r in rows if r['tool']!='normal'])} tools, "
          f"<0.8 recall: {len(low)}")
    for r in low:
        print(f"  LOW {r['tool']}: {r['recall']:.2f} (n={r['n']})")

    # ---- B. scenario split ----
    tr, va, te, te_idx, held = split_scenario(d)
    model2 = train_model(tr, va)
    th2 = tune_threshold(model2, va, va["y"])
    m2 = eval_split(model2, te, te["y"], threshold=th2)
    m2_0 = eval_split(model2, te, te["y"], threshold=0.5)
    report["scenario_split"] = {"held_out_tools": held,
                                "fixed_0.5": m2_0, "tuned": m2}
    print("\n=== B. 按工具留出 (未见过的工具, %d 个) ===" % len(held))
    print("held-out:", ", ".join(held))
    print(f"固定阈值0.5: recall={m2_0['recall']:.3f} precision={m2_0['precision']:.3f} "
          f"F1={m2_0['f1']:.3f} specificity={m2_0['specificity']:.3f}")
    print(f"recall={m2['recall']:.3f} precision={m2['precision']:.3f} "
          f"F1={m2['f1']:.3f} AUROC={m2['auroc']:.3f} AUPRC={m2['auprc']:.3f} "
          f"specificity={m2['specificity']:.3f}  (n={m2['n']}, th={th2:.2f})")
    rows2 = per_tool_recall(model2, te, te["y"],
                            [d["tools"][i] for i in te_idx], threshold=0.5)
    report["scenario_split_per_tool"] = rows2
    for r in sorted(rows2, key=lambda x: x["recall"]):
        if r["tool"] == "normal":
            print(f"  normal: recall={r['recall']:.3f} (n={r['n']}, fp={r['fp']})")
        else:
            print(f"  {r['tool']:16s} recall={r['recall']:.3f} (n={r['n']})")

    # ---- C. brute-force / port-scan detection ----
    print("\n=== C. 爆破/扫描检测（含跨流 burst 特征后重训） ===")
    bf_cases = [
        ("C1 同分布留出 30%", (), 0.3),
        ("C2 跨模式: 未见 SYN 扫描", ("scan_syn",), 0.0),
        ("C3 跨模式: 未见 SSH 爆破", ("bf_ssh",), 0.0),
        ("C4 跨模式: 未见 HTTP 爆破", ("bf_http",), 0.0),
    ]
    report["bruteforce"] = {}
    for label, held, frac in bf_cases:
        tr, va, te, te_idx = split_bf(d, held_bf=held, bf_test_frac=frac)
        model_bf = train_model(tr, va)
        m = bf_report(model_bf, te, te_idx, d, label)
        report["bruteforce"][label] = m

    with open(os.path.join(OUT, "report.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"\nreport -> {os.path.join(OUT, 'report.json')}")


if __name__ == "__main__":
    main()
