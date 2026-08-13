#!/usr/bin/env python3
"""Evaluate trained checkpoints on real-traffic pcaps (per-flow scores + FPR).

Usage:
  python3 ml/eval_real_traffic.py \
      --models "PATH,variant,dual" [...] [--pcaps data/captures/real_traffic*.pcap]

  variant: flat|grouped|multicol|grouped_multicol ; dual: 0|1
"""

import argparse
import glob
import os
import sys

import numpy as np
import torch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import build_dataset as B
from predict_pcap import flows_to_tensors
from train_transformer import DEVICE, FlowTransformer


def score_model(model, pcaps):
    probs = []
    for pcap in pcaps:
        flows = B.extract_flows(pcap)
        tens = flows_to_tensors(flows)
        if tens is None:
            continue
        with torch.no_grad():
            logit = model(**{k: v.to(DEVICE) for k, v in tens.items()}).cpu().numpy()
        probs.append(1 / (1 + np.exp(-logit)))
    return np.concatenate(probs) if probs else np.zeros(0)


def infer_meta_dim(pcaps):
    """Meta dimension is feature-config dependent; derive it from the pcaps
    so model checkpoints built with extra feature groups load correctly."""
    for pcap in pcaps:
        flows = B.extract_flows(pcap)
        tens = flows_to_tensors(flows)
        if tens is not None:
            return int(tens["X_meta"].shape[1])
    return 55


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", nargs="+", required=True,
                    help="checkpoint specs PATH,variant,dual")
    ap.add_argument("--pcaps", nargs="+",
                    default=sorted(glob.glob("data/captures/real_traffic*.pcap")))
    args = ap.parse_args()

    print(f"pcaps: {len(args.pcaps)}")
    meta_dim = infer_meta_dim(args.pcaps)
    header = f"{'model':34s} {'flows':>6s} {'>0.5':>5s} {'>0.90':>6s} {'FPR@0.5':>8s} {'FPR@0.90':>9s} {'mean':>6s} {'max':>6s} {'p99':>6s}"
    print(header)
    print("-" * len(header))
    for spec in args.models:
        parts = spec.split(",")
        path, variant, dual = parts[0], parts[1], parts[2] == "1"
        model = FlowTransformer(variant=variant, dual=dual, meta_dim=meta_dim)
        model.load_state_dict(torch.load(path, weights_only=True,
                                         map_location="cpu"))
        model.to(DEVICE).eval()
        p = score_model(model, args.pcaps)
        n = len(p)
        n05 = int((p >= 0.5).sum())
        n90 = int((p >= 0.90).sum())
        name = os.path.basename(path)
        print(f"{name:34s} {n:6d} {n05:5d} {n90:6d} "
              f"{n05 / n:8.4f} {n90 / n:9.4f} "
              f"{p.mean():6.3f} {p.max():6.3f} "
              f"{np.percentile(p, 99):6.3f}")


if __name__ == "__main__":
    main()
