#!/usr/bin/env python3
"""Ensemble evaluation (FP-minimization config).

Loads the three seed checkpoints of the 105-dim all-features five model,
averages their per-flow scores, applies the SYN-only veto (a flow that saw a
SYN but no SYN-ACK and no payload is treated as benign noise), and reports
FPR/recall at a configurable threshold.

Usage:
  TFLAB_FEATURES=base,http,multiscale,handshake,shape,lifecycle,tlsmeta,\
burstshape python3 ml/eval_ensemble.py --threshold 0.9 <pcap...>
"""
import argparse
import os
import sys

import numpy as np
import torch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import build_dataset as B  # noqa: E402
from five_model import FlowTransformerFive, flows_to_tensors_five  # noqa: E402

DEFAULT_SEEDS = ["five_pre_allfts", "five_pre_allfts_s1", "five_pre_allfts_s2"]


def syn_only(f):
    """SYN-only flow: no SYN-ACK and no payload (probe/noise morphology)."""
    return f["synonly"] > 0 and f["synack"] == 0 and not f["payload_seen"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--threshold", type=float, default=0.9)
    ap.add_argument("--no-veto", action="store_true",
                    help="disable the SYN-only veto")
    ap.add_argument("--d_model", type=int, default=64)
    ap.add_argument("--layers", type=int, default=2)
    ap.add_argument("--meta-dim", type=int, default=105)
    ap.add_argument("--model-dir", default="ml/models")
    ap.add_argument("pcaps", nargs="+")
    args = ap.parse_args()
    cfg = B.five_group_config()
    kw = dict(zip(["fd_groups_idx", "cd_groups_idx", "flow_int_vocab",
                   "flow_int_group_ids", "cross_int_vocab",
                   "cross_int_group_ids"], cfg))
    models = []
    for tag in DEFAULT_SEEDS:
        m = FlowTransformerFive(d_model=args.d_model, layers=args.layers,
                                inner_attn=False, cross_attn=False,
                                attn_mode="replace", dual_cls="pre",
                                slim=False, head_mode="mlp",
                                dual_head=False,
                                branch_mask=(True, True, True, True),
                                meta_dim=args.meta_dim, **kw)
        m.load_state_dict(torch.load(
            os.path.join(args.model_dir, f"flow_transformer_five_{tag}.pt"),
            weights_only=True, map_location="cpu"))
        m.eval()
        models.append(m)
    for p in args.pcaps:
        flows = B.extract_flows(p)
        tens = flows_to_tensors_five(flows)
        with torch.no_grad():
            ps = [torch.sigmoid(
                m(**{k: v for k, v in tens.items()})).numpy().ravel()
                for m in models]
        avg = np.mean(ps, axis=0)
        if not args.no_veto:
            avg = avg * np.array(
                [0.0 if syn_only(f) else 1.0 for f in flows])
        hit = int((avg >= args.threshold).sum())
        print(f"{os.path.basename(p)}: flows={len(avg)} "
              f"FPR@{args.threshold}={hit}/{len(avg)} "
              f"({100 * hit / len(avg):.2f}%)  "
              f"mean={avg.mean():.3f} max={avg.max():.3f} "
              f"p99={np.percentile(avg, 99):.3f}")


if __name__ == "__main__":
    main()
