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
import time

import numpy as np
import torch
import torch.nn as nn
from sklearn.metrics import (auc, confusion_matrix, precision_recall_curve,
                             roc_auc_score, roc_curve)

DEVICE = "cuda" if torch.cuda.is_available() else "cpu"  # GPU when available
DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "dataset.pt")
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")

# Semantic grouping plans for the 55-dim meta vector (indexes into meta_names):
#   0-2   TLS (is_tls / has_sni / tls13)
#   3-6   duration + volume (tot_c / tot_s / n_events)
#   7-9   dport + cross-flow scan features (same_port_burst / ports_sweep)
#   10-14 proto sizes (ch_len / sh_len / req_resp_ratio / max_rec / estab)
#   15    distinct_dsts (cross-flow, scan-related)
#   16-20 CIC duration/counts/bytes
#   21-28 CIC packet-length stats
#   29-36 CIC fwd/bwd IAT stats
#   37-40 CIC flow IAT stats
#   41-45 CIC TCP flags
#   46    CIC down/up ratio
#   47-54 CIC active/idle stats
GROUP_PLANS = {
    "coarse": [list(range(0, 16)), list(range(16, 55))],
    "mid": [
        list(range(0, 7)),    # TLS + duration + volume
        [7, 8, 9, 15],        # dport + scan features
        list(range(10, 15)),  # proto sizes
        list(range(16, 21)),  # cic duration/counts/bytes
        list(range(21, 29)),  # cic len stats
        list(range(29, 41)),  # cic iat stats
        list(range(41, 47)),  # cic flags + ratio
        list(range(47, 55)),  # cic active/idle
    ],
    "fine": [
        list(range(0, 3)),    # TLS
        list(range(3, 7)),    # duration + volume
        [7, 8, 9, 15],        # dport + scan features
        list(range(10, 15)),  # proto sizes
        list(range(16, 21)),  # cic duration/counts/bytes
        list(range(21, 29)),  # cic len stats
        list(range(29, 37)),  # cic fwd/bwd iat
        list(range(37, 41)),  # cic flow iat
        list(range(41, 46)),  # cic flags
        [46],                 # cic down/up ratio
        list(range(47, 55)),  # cic active/idle
    ],
}


class _CrossLayer(nn.Module):
    def __init__(self, d, rank):
        super().__init__()
        self.u = nn.Linear(d, rank, bias=False)
        self.v = nn.Linear(rank, d, bias=False)
        self.b = nn.Parameter(torch.zeros(d))

    def forward(self, x0, x):
        return x0 * (self.v(self.u(x)) + self.b) + x


class CrossNet(nn.Module):
    """DCN-V2 low-rank cross layers: x_{l+1} = x0 * (V(U^T x_l) + b) + x_l."""
    def __init__(self, d, layers=2, rank=8):
        super().__init__()
        self.layers = nn.ModuleList(
            [_CrossLayer(d, rank) for _ in range(layers)])

    def forward(self, x):
        x0 = x
        for l in self.layers:
            x = l(x0, x)
        return x


class DCNGroup(nn.Module):
    """QueryFormer-style per-group feature block:
    cross network (explicit feature crossing) + deep MLP, concat -> token."""
    def __init__(self, in_dim, d_model, cross_layers=2, rank=8,
                 hidden=64, dropout=0.1):
        super().__init__()
        self.cross = CrossNet(in_dim, layers=cross_layers, rank=rank)
        self.deep = nn.Sequential(
            nn.Linear(in_dim, hidden), nn.GELU(), nn.Dropout(dropout),
            nn.Linear(hidden, d_model))
        self.out = nn.Linear(in_dim + d_model, d_model)

    def forward(self, x):
        c = self.cross(x)
        d = self.deep(x)
        return self.out(torch.cat([c, d], dim=-1))


class FlowTransformer(nn.Module):
    """Fused meta + event-sequence Transformer.

    variant (QueryFormer-inspired ablations):
      flat              : meta -> one projection, added to the CLS token (baseline)
      grouped           : meta split by semantics (behavior 16 / CIC 39),
                          each group projected to its own token (2 meta tokens)
      multicol          : H independent meta projections (multi-view), averaged
                          into the CLS token
      grouped_multicol  : grouped tokens x H views each (both ideas combined)
    """
    def __init__(self, d_model=64, nhead=4, layers=2, ff=128, meta_dim=55,
                 max_len=96, dropout=0.1, variant="flat", h_cols=4,
                 meta_split=16, group_plan="coarse", dcn=False, dual=False):
        super().__init__()
        self.variant = variant
        if dual and variant not in ("flat", "grouped"):
            raise ValueError("--dual is only supported for flat / grouped variants")
        self.dir_emb = nn.Embedding(2, d_model)
        self.sz_emb = nn.Embedding(32, d_model)
        self.dt_emb = nn.Embedding(12, d_model)
        if variant in ("grouped", "grouped_multicol"):
            self.group_plan = group_plan
            self.group_idx = GROUP_PLANS[group_plan]
            self.extra_tokens = len(self.group_idx)
        else:
            self.group_idx = []
            self.extra_tokens = 0
        # keep (max_len+1) for flat/multicol so old checkpoints still load
        self.pos = nn.Parameter(torch.randn(
            1, max_len + 1 + self.extra_tokens, d_model) * 0.02)
        self.cls = nn.Parameter(torch.randn(d_model) * 0.02)
        if variant == "flat":
            self.meta_proj = nn.Linear(meta_dim, d_model)
            self.dcn_proj = DCNGroup(meta_dim, d_model) if (dcn or dual) else None
        elif variant == "grouped":
            self.group_projs = nn.ModuleList(
                [(DCNGroup(len(g), d_model) if (dcn or dual)
                  else nn.Linear(len(g), d_model)) for g in self.group_idx])
            # dual: one global direct path into CLS, bypassing attention
            self.direct_proj = nn.Linear(meta_dim, d_model) if dual else None
        elif variant == "multicol":
            self.meta_cols = nn.ModuleList(
                [(DCNGroup(meta_dim, d_model) if dcn
                  else nn.Linear(meta_dim, d_model)) for _ in range(h_cols)])
        elif variant == "grouped_multicol":
            self.group_cols = nn.ModuleList([
                nn.ModuleList([(DCNGroup(len(g), d_model) if dcn
                                else nn.Linear(len(g), d_model))
                               for _ in range(h_cols)])
                for g in self.group_idx])
        else:
            raise ValueError(f"unknown variant: {variant}")
        enc = nn.TransformerEncoderLayer(
            d_model=d_model, nhead=nhead, dim_feedforward=ff,
            dropout=dropout, batch_first=True, activation="gelu")
        self.enc = nn.TransformerEncoder(enc, num_layers=layers)
        self.head = nn.Sequential(
            nn.LayerNorm(d_model), nn.Dropout(dropout), nn.Linear(d_model, 1))

    def forward(self, X_dir, X_sz, X_dt, X_mask, X_meta):
        B, L = X_dir.shape
        ev = self.dir_emb(X_dir) + self.sz_emb(X_sz) + self.dt_emb(X_dt)
        cls = self.cls.unsqueeze(0).expand(B, -1)
        if self.variant == "flat":
            cls = cls + self.meta_proj(X_meta)
            if self.dcn_proj is not None:
                cls = cls + self.dcn_proj(X_meta)
            meta_tok = []
        elif self.variant == "grouped":
            meta_tok = [p(X_meta[:, g])
                        for p, g in zip(self.group_projs, self.group_idx)]
            if self.direct_proj is not None:
                cls = cls + self.direct_proj(X_meta)
        elif self.variant == "multicol":
            views = torch.stack([c(X_meta) for c in self.meta_cols], dim=1)
            cls = cls + views.mean(dim=1)
            meta_tok = []
        else:  # grouped_multicol
            meta_tok = [
                torch.stack([c(X_meta[:, g]) for c in cols], dim=1).mean(dim=1)
                for cols, g in zip(self.group_cols, self.group_idx)]
        if meta_tok:
            seq = torch.cat([cls.unsqueeze(1)] + [t.unsqueeze(1) for t in meta_tok]
                            + [ev], dim=1)
            pad = torch.cat([torch.zeros(B, 1 + len(meta_tok),
                                         device=X_mask.device), X_mask], dim=1)
        else:
            seq = torch.cat([cls.unsqueeze(1), ev], dim=1)
            pad = torch.cat([torch.zeros(B, 1, device=X_mask.device), X_mask], dim=1)
        seq = seq + self.pos[:, :seq.size(1)]
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


def train_model(tr, va, d_model=64, layers=2, variant="flat", h_cols=4,
                group_plan="coarse", dcn=False, dual=False):
    torch.manual_seed(0)
    meta_dim = int(tr["X_meta"].shape[1])
    raw_model = FlowTransformer(d_model=d_model, layers=layers,
                                variant=variant, h_cols=h_cols,
                                group_plan=group_plan, dcn=dcn,
                                dual=dual, meta_dim=meta_dim).to(DEVICE)
    model = raw_model
    # larger batch -> fewer Python iterations (main overhead at this scale);
    # sqrt-scaled LR keeps the optimization dynamics comparable
    bs = 512
    lr = 2e-3
    opt = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
    try:
        model = torch.compile(model)  # Triton on CUDA; falls back if unsupported
    except Exception:
        pass
    max_epochs = 30
    sched = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=max_epochs)
    lossf = nn.BCEWithLogitsLoss()
    t0 = time.time()

    # move the whole dataset to the device once; index slices directly on
    # the device (avoids per-batch CPU->GPU copies, the main bottleneck)
    Xtr = {k: v.to(DEVICE) for k, v in tr.items() if k.startswith("X")}
    ytr = tr["y"].float().to(DEVICE)
    Xva = {k: v.to(DEVICE) for k, v in va.items() if k.startswith("X")}
    yva_cpu = va["y"].float()
    ytr = ytr * 0.9 + 0.05  # label smoothing, prevents logit saturation
    n = len(ytr)
    best, patience, best_state = 1e9, 0, None
    ep_t0 = time.time()
    for epoch in range(max_epochs):
        model.train()
        perm = torch.randperm(n)
        tl = 0.0
        for i in range(0, n, bs):
            idx = perm[i:i + bs]
            b = {k: v[idx] for k, v in Xtr.items()}
            yb = ytr[idx]
            opt.zero_grad()
            out = model(**b)
            loss = lossf(out, yb)
            loss.backward()
            opt.step()
            tl += loss.item() * len(idx)
        sched.step()
        model.eval()
        with torch.no_grad():
            vout = model(**Xva).cpu()
            vloss = lossf(vout, yva_cpu).item()
            yv = yva_cpu.numpy()
            vp = torch.sigmoid(vout).numpy()
            try:
                vauroc = roc_auc_score(yv, vp)
            except ValueError:
                vauroc = float("nan")
        print(f"  [epoch {epoch+1:2d}/{max_epochs}] loss={tl/max(1,n):.4f} "
              f"val={vloss:.4f} val_auc={vauroc:.4f} "
              f"lr={sched.get_last_lr()[0]:.2e} "
              f"elapsed={time.time()-t0:.0f}s "
              f"ep={time.time()-ep_t0:.2f}s", flush=True)
        ep_t0 = time.time()
        # early stop: require a meaningful improvement (>0.1% relative) so
        # noisy val-loss fluctuations do not keep resetting the counter
        if vloss < best * (1 - 1e-3):
            best, patience = vloss, 0
            best_state = {k: v.detach().cpu().clone() for k, v in raw_model.state_dict().items()}
        else:
            patience += 1
            if patience >= 5:
                print(f"  [early stop at epoch {epoch+1} (best val={best:.4f})]", flush=True)
                break
    raw_model.load_state_dict(best_state)
    return raw_model


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


def run_tool_kfold(d, k=5, seed=42, variant="flat", h_cols=4,
                   group_plan="coarse", dcn=False, dual=False):
    """Tool-level k-fold cross-validation: each fold holds out a random 1/k
    of the tools entirely; metrics are accumulated across all folds so every
    tool is tested as "unseen" exactly once."""
    rng = np.random.RandomState(seed)
    tools = sorted({t for t in d["tools"] if t})
    rng.shuffle(tools)
    folds = [set(tools[i::k]) for i in range(k)]
    norm_idx = [i for i, t in enumerate(d["tools"]) if not t]
    rng.shuffle(norm_idx)
    kn = int(len(norm_idx) * 0.7)
    kn2 = int(len(norm_idx) * 0.85)

    def sub(idx):
        return {kk: v[torch.from_numpy(np.asarray(idx))] for kk, v in d.items()
                if kk in ("X_dir", "X_sz", "X_dt", "X_mask", "X_meta", "y")}

    agg = {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "auc": [], "n": 0}
    agg05 = {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "n": 0}
    per_tool = {}
    for fi, held in enumerate(folds):
        tr_idx = [i for i, t in enumerate(d["tools"]) if t and t not in held]
        r2 = np.random.RandomState(fi)
        r2.shuffle(tr_idx)
        kt = int(len(tr_idx) * 0.85)
        train = tr_idx[:kt] + norm_idx[:kn]
        val = tr_idx[kt:] + norm_idx[kn:kn2]
        test = [i for i, t in enumerate(d["tools"]) if t in held] + norm_idx[kn2:]
        model = train_model(sub(train), sub(val), variant=variant,
                            h_cols=h_cols, group_plan=group_plan, dcn=dcn,
                            dual=dual)
        te = sub(test)
        m = eval_split(model, te, te["y"])
        # tune the decision threshold on this fold's validation set
        th = tune_threshold(model, sub(val), sub(val)["y"])
        with torch.no_grad():
            Xf = {kk: v.to(DEVICE) for kk, v in te.items() if kk.startswith("X")}
            pv = torch.sigmoid(model(**Xf)).cpu().numpy()
        yv = te["y"].numpy()
        pred = (pv >= th).astype(int)
        agg["tp"] += int(((pred == 1) & (yv == 1)).sum())
        agg["fp"] += int(((pred == 1) & (yv == 0)).sum())
        agg["fn"] += int(((pred == 0) & (yv == 1)).sum())
        agg["tn"] += int(((pred == 0) & (yv == 0)).sum())
        agg["n"] += m["n"]
        m05 = eval_split(model, te, te["y"], threshold=0.5)
        agg05["tp"] += m05["tp"]; agg05["fp"] += m05["fp"]
        agg05["fn"] += m05["fn"]; agg05["tn"] += m05["tn"]; agg05["n"] += m05["n"]
        if not np.isnan(m["auroc"]):
            agg["auc"].append(m["auroc"])
        model.eval()
        with torch.no_grad():
            Xf = {kk: v.to(DEVICE) for kk, v in te.items() if kk.startswith("X")}
            p = torch.sigmoid(model(**Xf)).cpu().numpy()
        for i, t in enumerate([d["tools"][j] for j in test]):
            if not t:
                continue
            r = per_tool.setdefault(t, {"n": 0, "tp": 0})
            r["n"] += 1
            r["tp"] += int(p[i] >= th and te["y"][i].item() == 1)

    tp, fp, fn, tn = agg["tp"], agg["fp"], agg["fn"], agg["tn"]
    recall = tp / (tp + fn) if tp + fn else 0.0
    precision = tp / (tp + fp) if tp + fp else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    res = {
        "recall": recall, "precision": precision, "f1": f1,
        "specificity": tn / (tn + fp) if tn + fp else 0.0,
        "auroc": float(np.mean(agg["auc"])) if agg["auc"] else float("nan"),
        "n": agg["n"], "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "k": k,
    }
    t5, f5 = agg05["tp"], agg05["fp"]
    res["fixed_0.5"] = {
        "recall": t5 / (t5 + agg05["fn"]) if t5 + agg05["fn"] else 0.0,
        "precision": t5 / (t5 + f5) if t5 + f5 else 0.0,
        "f1": 2 * t5 / (2 * t5 + f5 + agg05["fn"]) if 2 * t5 + f5 + agg05["fn"] else 0.0,
        "specificity": agg05["tn"] / (agg05["tn"] + f5) if agg05["tn"] + f5 else 0.0,
        "tp": t5, "fp": f5, "fn": agg05["fn"], "tn": agg05["tn"],
    }
    print("\n=== B. 工具级 %d 折交叉验证（全部工具均作为未见测试过一次） ===" % k)
    print(f"recall={recall:.3f} precision={precision:.3f} F1={f1:.3f} "
          f"AUROC={res['auroc']:.3f} specificity={res['specificity']:.3f} (n={agg['n']})")
    print(f"固定阈值0.5: recall={res['fixed_0.5']['recall']:.3f} "
          f"specificity={res['fixed_0.5']['specificity']:.3f} "
          f"(tp={t5}, fp={f5})")
    low = [(t, r) for t, r in sorted(per_tool.items(), key=lambda x: x[1]["tp"] / max(1, x[1]["n"]))
           if r["tp"] / max(1, r["n"]) < 0.8]
    print(f"低于 0.8 recall 的工具: {len(low)}")
    for t, r in low:
        print(f"  {t:16s} recall={r['tp']/max(1,r['n']):.2f} (n={r['n']})")
    res["per_tool"] = per_tool
    return res


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
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", choices=["random", "tools", "ab", "full"],
                    default="ab",
                    help="random=A only; tools=B (tool k-fold) only; "
                         "ab=A+B (default); full=+brute-force variants")
    ap.add_argument("--seed", type=int, default=42,
                    help="RNG seed for the tool-level k-fold split")
    ap.add_argument("--d_model", type=int, default=64,
                    help="Transformer embedding width")
    ap.add_argument("--layers", type=int, default=2,
                    help="Transformer encoder layers")
    ap.add_argument("--tag", type=str, default="",
                    help="model filename suffix (flow_transformer_<tag>.pt)")
    ap.add_argument("--variant", type=str,
                    choices=["flat", "grouped", "multicol", "grouped_multicol"],
                    default="flat",
                    help="meta-input architecture (QueryFormer-inspired ablation)")
    ap.add_argument("--h_cols", type=int, default=4,
                    help="number of independent meta projections (multicol)")
    ap.add_argument("--group_plan", type=str,
                    choices=list(GROUP_PLANS), default="coarse",
                    help="meta grouping granularity (grouped / grouped_multicol)")
    ap.add_argument("--dcn", action="store_true",
                    help="use DCN-V2 (cross + deep) instead of Linear per group")
    ap.add_argument("--dual", action="store_true",
                    help="dual path: keep Linear direct-to-CLS and add DCN in parallel")
    args = ap.parse_args()
    d = torch.load(DATA, weights_only=False)
    for k in ("X_dir", "X_sz", "X_dt", "X_mask", "X_meta"):
        d[k] = d[k].float() if k in ("X_mask", "X_meta") else d[k].long()

    os.makedirs(OUT, exist_ok=True)
    report = {"dataset": {"n": len(d["y"]),
                          "malicious": int(d["y"].sum()),
                          "normal": len(d["y"]) - int(d["y"].sum())},
              "config": {"variant": args.variant, "h_cols": args.h_cols,
                         "d_model": args.d_model, "layers": args.layers,
                         "seed": args.seed, "group_plan": args.group_plan,
                         "dcn": args.dcn, "dual": args.dual}}

    # ---- A. random split ----
    if args.split in ("random", "ab", "full"):
        print("\n=== 训练模型 A: 随机分割 ===", flush=True)
        tr, va, te, te_idx = split_random(d)
        model = train_model(tr, va, d_model=args.d_model, layers=args.layers,
                            variant=args.variant, h_cols=args.h_cols,
                            group_plan=args.group_plan, dcn=args.dcn,
                            dual=args.dual)
        suffix = f"_{args.tag}" if args.tag else ""
        torch.save(model.state_dict(),
                   os.path.join(OUT, f"flow_transformer{suffix}.pt"))
        report["params"] = sum(p.numel() for p in model.parameters())
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
    if args.split in ("tools", "ab", "full"):
        print("\n=== B. 工具级 K 折交叉验证 ===", flush=True)
        report["scenario_split"] = run_tool_kfold(
            d, seed=args.seed, variant=args.variant, h_cols=args.h_cols,
            group_plan=args.group_plan, dcn=args.dcn, dual=args.dual)

    # ---- C. brute-force / port-scan detection ----
    if args.split == "full":
        print("\n=== C. 爆破/扫描检测（含跨流 burst 特征后重训） ===")
        bf_cases = [
            ("C1 同分布留出 30%", (), 0.3),
            ("C2 跨模式: 未见 SYN 扫描", ("scan_syn",), 0.0),
            ("C3 跨模式: 未见 SSH 爆破", ("bf_ssh",), 0.0),
            ("C4 跨模式: 未见 HTTP 爆破", ("bf_http",), 0.0),
        ]
        report["bruteforce"] = {}
        for label, held, frac in bf_cases:
            print(f"\n=== 训练模型 {label} ===", flush=True)
            tr, va, te, te_idx = split_bf(d, held_bf=held, bf_test_frac=frac)
            model_bf = train_model(tr, va)
            m = bf_report(model_bf, te, te_idx, d, label)
            report["bruteforce"][label] = m

    rpath = os.path.join(OUT, f"report_{args.tag}.json" if args.tag else "report.json")
    with open(rpath, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"\nreport -> {rpath}")


if __name__ == "__main__":
    main()
