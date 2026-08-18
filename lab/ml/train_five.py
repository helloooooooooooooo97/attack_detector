#!/usr/bin/env python3
"""Standalone trainer for the five-type architecture (additive; existing
training code is untouched). Mirrors the production protocol: A random split
(seed 42) + B tool-level 5-fold CV, batch 512, lr 2e-3, 30 epoch early stop.

Usage: python3 ml/train_five.py --tag <tag> [--d_model 64] [--layers 2]
"""

import argparse
import json
import os
import sys
import time

import numpy as np
import torch
import torch.nn as nn

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import build_dataset as B  # noqa: E402
from five_model import FlowTransformerFive  # noqa: E402
from train_transformer import (  # noqa: E402
    DEVICE, eval_split, metrics, tune_threshold)


LAB = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "dataset.pt")
MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
REPORT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")


def split_five(d, seed=42):
    """Same flow-level 70/15/15 split (seed 42) as the production A protocol,
    including the integer feature tensors."""
    idx = np.arange(len(d["y"]))
    rng = np.random.RandomState(seed)
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
                if k.startswith("X") or k == "y"}

    return (sub(np.concatenate([trp, trn])),
            sub(np.concatenate([valp, valn])),
            sub(np.concatenate([tep, ten])),
            np.concatenate([tep, ten]))


def train_model_five(tr, va, d_model=64, layers=2, bs=512, lr=2e-3,
                     max_epochs=30, inner_attn=True, cross_attn=True,
                     attn_mode="replace", dual_cls=False, slim=False,
                     seed=0, head_mode="mlp", dual_head=False,
                     branch_mask=(True, True, True, True), meta_dim=73):
    torch.manual_seed(seed)
    cfg = B.five_group_config()
    raw_model = FlowTransformerFive(d_model=d_model, layers=layers,
                                    inner_attn=inner_attn,
                                    cross_attn=cross_attn,
                                    attn_mode=attn_mode,
                                    dual_cls=dual_cls, slim=slim,
                                    head_mode=head_mode,
                                    dual_head=dual_head,
                                    branch_mask=branch_mask,
                                    meta_dim=meta_dim,
                                    fd_groups_idx=cfg[0], cd_groups_idx=cfg[1],
                                    flow_int_vocab=cfg[2],
                                    flow_int_group_ids=cfg[3],
                                    cross_int_vocab=cfg[4],
                                    cross_int_group_ids=cfg[5]).to(DEVICE)
    model = raw_model
    opt = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
    try:
        model = torch.compile(model)
    except Exception:
        pass
    sched = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=max_epochs)
    lossf = nn.BCEWithLogitsLoss()
    t0 = time.time()
    Xtr = {k: v.to(DEVICE) for k, v in tr.items() if k.startswith("X")}
    ytr = (tr["y"].float().to(DEVICE) * 0.9 + 0.05)
    Xva = {k: v.to(DEVICE) for k, v in va.items() if k.startswith("X")}
    yva_cpu = va["y"].float()
    n = len(ytr)
    best, patience, best_state = 1e9, 0, None
    for epoch in range(max_epochs):
        model.train()
        perm = torch.randperm(n)
        tl = 0.0
        for i in range(0, n, bs):
            idx = perm[i:i + bs]
            b = {k: v[idx] for k, v in Xtr.items()}
            opt.zero_grad()
            out = model(**b)
            loss = lossf(out, ytr[idx])
            loss.backward()
            opt.step()
            tl += loss.item() * len(idx)
        sched.step()
        model.eval()
        with torch.no_grad():
            vout = model(**Xva).cpu()
            vloss = lossf(vout, yva_cpu).item()
        if vloss < best * (1 - 1e-3):
            best, patience = vloss, 0
            best_state = {k: v.detach().cpu().clone()
                          for k, v in raw_model.state_dict().items()}
        else:
            patience += 1
            if patience >= 5:
                break
        print(f"  [epoch {epoch+1:2d}/{max_epochs}] loss={tl/max(1,n):.4f} "
              f"val={vloss:.4f} elapsed={time.time()-t0:.0f}s", flush=True)
    raw_model.load_state_dict(best_state)
    return raw_model


def run_tool_kfold_five(d, k=5, seed=42, d_model=64, layers=2,
                        inner_attn=True, cross_attn=True, attn_mode="replace",
                        dual_cls=False, slim=False, head_mode="mlp",
                        dual_head=False, branch_mask=(True, True, True, True),
                        meta_dim=73):
    rng = np.random.RandomState(seed)
    tools = sorted({t for t in d["tools"] if t})
    rng.shuffle(tools)
    folds = [set(tools[i::k]) for i in range(k)]
    norm_idx = [i for i, t in enumerate(d["tools"]) if not t]
    rng.shuffle(norm_idx)
    kn = int(len(norm_idx) * 0.7)
    kn2 = int(len(norm_idx) * 0.85)

    def sub(idx):
        return {kk: v[torch.from_numpy(np.asarray(idx))]
                for kk, v in d.items() if kk.startswith("X") or kk == "y"}

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
        test = ([i for i, t in enumerate(d["tools"]) if t in held]
                + norm_idx[kn2:])
        model = train_model_five(sub(train), sub(val),
                                 d_model=d_model, layers=layers,
                                 inner_attn=inner_attn, cross_attn=cross_attn,
                                 attn_mode=attn_mode, dual_cls=dual_cls,
                                 slim=slim, head_mode=head_mode,
                                 dual_head=dual_head,
                                 branch_mask=branch_mask, meta_dim=meta_dim)
        te = sub(test)
        m = eval_split(model, te, te["y"])
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
        agg05["tp"] += m05["tp"]
        agg05["fp"] += m05["fp"]
        agg05["fn"] += m05["fn"]
        agg05["tn"] += m05["tn"]
        agg05["n"] += m05["n"]
        if not np.isnan(m["auroc"]):
            agg["auc"].append(m["auroc"])
        for i, t in enumerate([d["tools"][j] for j in test]):
            if not t:
                continue
            r = per_tool.setdefault(t, {"n": 0, "tp": 0})
            r["n"] += 1
            r["tp"] += int(pv[i] >= th and te["y"][i].item() == 1)
    tp, fp, fn, tn = agg["tp"], agg["fp"], agg["fn"], agg["tn"]
    rec = tp / (tp + fn) if tp + fn else 0.0
    prec = tp / (tp + fp) if tp + fp else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    tp5, fp5, fn5, tn5 = (agg05["tp"], agg05["fp"],
                          agg05["fn"], agg05["tn"])
    return {
        "recall": rec, "precision": prec, "f1": f1,
        "specificity": tn / (tn + fp) if tn + fp else 0.0,
        "auroc": float(np.mean(agg["auc"])) if agg["auc"] else float("nan"),
        "n": agg["n"], "tp": tp, "fp": fp, "fn": fn, "tn": tn, "k": k,
        "fixed_0.5": {"recall": tp5 / (tp5 + fn5) if tp5 + fn5 else 0.0,
                      "tp": tp5, "fp": fp5, "fn": fn5, "tn": tn5},
        "per_tool": per_tool,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", required=True)
    ap.add_argument("--d_model", type=int, default=64)
    ap.add_argument("--layers", type=int, default=2)
    ap.add_argument("--no-inner-attn", action="store_true",
                    help="disable intra-branch self-attention")
    ap.add_argument("--no-cross-attn", action="store_true",
                    help="disable inter-branch cross-attention")
    ap.add_argument("--attn-mode", choices=["replace", "residual", "concat"],
                    default="replace",
                    help="how to fuse attention output with the direct path")
    ap.add_argument("--dual-cls", choices=["post", "pre"], default=None,
                    help="inject dual-style Linear+DCN meta onto CLS "
                         "post-encoder (post) or pre-encoder (pre, like dual)")
    ap.add_argument("--slim", action="store_true",
                    help="use Linear+GELU instead of DCN-V2 for small groups")
    ap.add_argument("--seed", type=int, default=42,
                    help="RNG seed for A split / B k-fold / init")
    ap.add_argument("--data", default=DATA,
                    help="dataset.pt path (default ml/data/dataset.pt)")
    ap.add_argument("--branch", default="fd,cd,fi,ci",
                    help="enabled branches, comma list of fd/cd/fi/ci")
    ap.add_argument("--head", choices=["mlp", "mlp_ln", "linear"],
                    default="mlp",
                    help="fusion head: mlp, mlp_ln (LayerNorm before final "
                         "linear), or linear (320->1)")
    ap.add_argument("--dual-head", action="store_true",
                    help="add dual-style LayerNorm->Linear head on CLS, "
                         "logits summed with five head")
    args = ap.parse_args()
    inner_attn = not args.no_inner_attn
    cross_attn = not args.no_cross_attn
    br = [b.strip() for b in args.branch.split(",") if b.strip()]
    branch_mask = ("fd" in br, "cd" in br, "fi" in br, "ci" in br)

    d = torch.load(args.data, weights_only=False)
    meta_dim = int(d["X_meta"].shape[1])
    for k in ("X_dir", "X_sz", "X_dt", "X_mask", "X_meta",
              "X_int_flow", "X_int_cross"):
        if k in d:
            d[k] = d[k].float() if k in ("X_mask", "X_meta") else d[k].long()
    os.makedirs(MODEL_DIR, exist_ok=True)
    os.makedirs(REPORT_DIR, exist_ok=True)
    report = {"dataset": {"n": len(d["y"]),
                          "malicious": int(d["y"].sum()),
                          "normal": len(d["y"]) - int(d["y"].sum())},
              "config": {"variant": "five", "tag": args.tag,
                         "d_model": args.d_model, "layers": args.layers}}

    print("=== A. 随机分割 ===")
    tr, va, te, te_idx = split_five(d, seed=args.seed)
    model = train_model_five(tr, va, d_model=args.d_model, layers=args.layers,
                             inner_attn=inner_attn, cross_attn=cross_attn,
                             attn_mode=args.attn_mode, dual_cls=args.dual_cls,
                             slim=args.slim, seed=args.seed,
                             head_mode=args.head, dual_head=args.dual_head,
                             branch_mask=branch_mask, meta_dim=meta_dim)
    torch.save(model.state_dict(),
               os.path.join(MODEL_DIR, f"flow_transformer_five_{args.tag}.pt"))
    report["params"] = sum(p.numel() for p in model.parameters())
    th = tune_threshold(model, va, va["y"])
    m = eval_split(model, te, te["y"], threshold=th)
    m0 = eval_split(model, te, te["y"], threshold=0.5)
    report["random_split"] = {"fixed_0.5": m0, "tuned": m}
    print(f"固定阈值0.5: recall={m0['recall']:.4f} spec={m0['specificity']:.4f}")
    print(f"tuned: recall={m['recall']:.4f} spec={m['specificity']:.4f} "
          f"AUROC={m['auroc']:.4f} (th={th:.2f}, params={report['params']})")

    print("\n=== B. 工具级 5 折 ===")
    report["scenario_split"] = run_tool_kfold_five(
        d, d_model=args.d_model, layers=args.layers,
        inner_attn=inner_attn, cross_attn=cross_attn,
        attn_mode=args.attn_mode, dual_cls=args.dual_cls, slim=args.slim,
        seed=args.seed, head_mode=args.head, dual_head=args.dual_head,
        branch_mask=branch_mask, meta_dim=meta_dim)
    report["config"]["inner_attn"] = inner_attn
    report["config"]["cross_attn"] = cross_attn
    report["config"]["attn_mode"] = args.attn_mode
    report["config"]["dual_cls"] = args.dual_cls
    report["config"]["slim"] = args.slim
    report["config"]["seed"] = args.seed
    report["config"]["head"] = args.head
    report["config"]["dual_head"] = args.dual_head
    report["config"]["branch"] = args.branch
    b = report["scenario_split"]
    print(f"recall={b['recall']:.4f} AUROC={b['auroc']:.4f} "
          f"fixed0.5 recall={b['fixed_0.5']['recall']:.4f}")

    rpath = os.path.join(REPORT_DIR, f"report_five_{args.tag}.json")
    with open(rpath, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"report -> {rpath}")


if __name__ == "__main__":
    main()
