#!/usr/bin/env python3
"""Run the trained FlowTransformer over arbitrary pcaps (per-flow scores).

Usage: python3 ml/predict_pcap.py [--model PATH] [--variant VARIANT]
                                  [--h_cols N] <pcap...>
"""

import argparse
import os
import sys

import numpy as np
import torch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import build_dataset as B
from train_transformer import FlowTransformer, DEVICE


def flows_to_tensors(flows):
    metas = [B.all_meta(c) for c in flows]
    B.cross_flow_meta(flows, metas)
    X_dir, X_sz, X_dt, X_mask, X_meta = [], [], [], [], []
    for c, meta in zip(flows, metas):
        evs = B.events_of(c)
        if not evs:
            continue
        n = min(len(evs), B.MAX_LEN)
        evs = evs[:n]
        X_dir.append([e[0] for e in evs])
        X_sz.append([B.size_bucket(e[1]) for e in evs])
        X_dt.append([B.dt_bucket(e[2]) for e in evs])
        X_mask.append([1.0] * n)
        X_meta.append(meta)
    if not X_dir:
        return None
    n = len(X_dir)
    a = lambda v: np.zeros((n, B.MAX_LEN), dtype=np.int64)
    ad = np.zeros((n, B.MAX_LEN), dtype=np.int64)
    az = np.zeros((n, B.MAX_LEN), dtype=np.int64)
    at = np.zeros((n, B.MAX_LEN), dtype=np.int64)
    am = np.zeros((n, B.MAX_LEN), dtype=np.float32)
    for i in range(n):
        ln = len(X_dir[i])
        ad[i, :ln] = X_dir[i]; az[i, :ln] = X_sz[i]
        at[i, :ln] = X_dt[i]; am[i, :ln] = X_mask[i]
    return {
        "X_dir": torch.from_numpy(ad).long(),
        "X_sz": torch.from_numpy(az).long(),
        "X_dt": torch.from_numpy(at).long(),
        "X_mask": torch.from_numpy(am).float(),
        "X_meta": torch.from_numpy(np.asarray(X_meta, dtype=np.float32)),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "reports",
        "flow_transformer.pt"), help="model checkpoint path")
    ap.add_argument("--variant", default="flat",
                    choices=["flat", "grouped", "multicol", "grouped_multicol"])
    ap.add_argument("--h_cols", type=int, default=4)
    ap.add_argument("--group_plan", default="coarse",
                    choices=["coarse", "mid", "fine"])
    ap.add_argument("--dcn", action="store_true",
                    help="load a DCN-V2 (cross + deep) meta block model")
    ap.add_argument("--dual", action="store_true",
                    help="load a dual-path model (Linear direct + DCN parallel)")
    ap.add_argument("pcaps", nargs="+")
    args = ap.parse_args()
    model = None
    for path in args.pcaps:
        flows = B.extract_flows(path)
        tens = flows_to_tensors(flows)
        if tens is None:
            print(f"{path}: 0 flows")
            continue
        if model is None:
            model = FlowTransformer(variant=args.variant, h_cols=args.h_cols,
                                    group_plan=args.group_plan, dcn=args.dcn,
                                    dual=args.dual,
                                    meta_dim=int(tens["X_meta"].shape[1]))
            model.load_state_dict(torch.load(
                model_path, weights_only=True, map_location="cpu"))
            model.to(DEVICE).eval()
        with torch.no_grad():
            logit = model(**{k: v.to(DEVICE) for k, v in tens.items()}).cpu().numpy()
        p = 1 / (1 + np.exp(-logit))
        pred = (p >= 0.5).astype(int)
        print(f"{path}: flows={len(flows)} "
              f"恶意概率 mean={p.mean():.3f} max={p.max():.3f} "
              f"判恶意 {pred.sum()}/{len(p)}")


if __name__ == "__main__":
    main()
