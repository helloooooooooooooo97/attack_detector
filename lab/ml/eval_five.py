#!/usr/bin/env python3
"""Evaluate a five-type checkpoint on real-traffic pcaps (per-flow FPR).

Usage: TFLAB_FEATURES=base,http,multiscale python3 ml/eval_five.py \
         --model ml/models/flow_transformer_five_<tag>.pt <pcap...>
"""

import argparse
import os
import sys

import numpy as np
import torch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import build_dataset as B  # noqa: E402
from five_model import FlowTransformerFive, flows_to_tensors_five  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
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
    ap.add_argument("--head", choices=["mlp", "mlp_ln", "linear"],
                    default="mlp",
                    help="fusion head: mlp, mlp_ln (LayerNorm before final "
                         "linear), or linear (320->1)")
    ap.add_argument("--dual-head", action="store_true",
                    help="add dual-style LayerNorm->Linear head on CLS, "
                         "logits summed with five head")
    ap.add_argument("--branch", default="fd,cd,fi,ci",
                    help="enabled branches, comma list of fd/cd/fi/ci")
    ap.add_argument("pcaps", nargs="+")
    args = ap.parse_args()
    br = [b.strip() for b in args.branch.split(",") if b.strip()]
    branch_mask = ("fd" in br, "cd" in br, "fi" in br, "ci" in br)

    meta_dim = 73
    for p in args.pcaps:
        t0 = flows_to_tensors_five(B.extract_flows(p))
        if t0 is not None:
            meta_dim = int(t0["X_meta"].shape[1])
            break
    cfg = B.five_group_config()
    model = FlowTransformerFive(d_model=args.d_model, layers=args.layers,
                                inner_attn=not args.no_inner_attn,
                                cross_attn=not args.no_cross_attn,
                                attn_mode=args.attn_mode,
                                dual_cls=args.dual_cls, slim=args.slim,
                                head_mode=args.head,
                                dual_head=args.dual_head,
                                branch_mask=branch_mask, meta_dim=meta_dim,
                                fd_groups_idx=cfg[0], cd_groups_idx=cfg[1],
                                flow_int_vocab=cfg[2],
                                flow_int_group_ids=cfg[3],
                                cross_int_vocab=cfg[4],
                                cross_int_group_ids=cfg[5])
    model.load_state_dict(torch.load(args.model, weights_only=True,
                                     map_location="cpu"))
    model.eval()
    for p in args.pcaps:
        flows = B.extract_flows(p)
        tens = flows_to_tensors_five(flows)
        if tens is None:
            print(f"{p}: 0 flows")
            continue
        with torch.no_grad():
            logit = model(**{k: v for k, v in tens.items()})
        prob = torch.sigmoid(logit).numpy().ravel()
        fp05 = int((prob >= 0.5).sum())
        fp90 = int((prob >= 0.90).sum())
        print(f"{os.path.basename(p)}: flows={len(prob)} "
              f"FPR@0.5={fp05}/{len(prob)} ({100*fp05/len(prob):.2f}%)  "
              f"FPR@0.90={fp90}  mean={prob.mean():.3f} max={prob.max():.3f} "
              f"p99={np.percentile(prob, 99):.3f}")


if __name__ == "__main__":
    main()
