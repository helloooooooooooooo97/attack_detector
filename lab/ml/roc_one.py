#!/usr/bin/env python3
"""Compute the A-test-set ROC curve for one checkpoint, saving an npz.

Run with the same TFLAB_FEATURES the model was trained with.
"""

import argparse
import os
import sys

import numpy as np
import torch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from train_transformer import FlowTransformer, split_random


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--dual", type=int, default=1)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    d = torch.load(args.dataset, weights_only=False)
    for k in ("X_dir", "X_sz", "X_dt", "X_mask", "X_meta"):
        d[k] = d[k].float() if k in ("X_mask", "X_meta") else d[k].long()
    tr, va, te, _ = split_random(d)
    Xf = {k: v for k, v in te.items() if k.startswith("X")}
    y = te["y"].numpy()

    m = FlowTransformer(variant="flat", dual=bool(args.dual),
                        meta_dim=int(te["X_meta"].shape[1]))
    m.load_state_dict(torch.load(args.model, weights_only=True,
                                 map_location="cpu"))
    m.eval()
    with torch.no_grad():
        p = torch.sigmoid(m(**Xf)).numpy().ravel()

    from sklearn.metrics import auc, roc_curve
    fpr, tpr, ths = roc_curve(y, p)
    np.savez(args.out, fpr=fpr, tpr=tpr, ths=ths, auc=auc(fpr, tpr),
             y=y, p=p)
    n_mal = int(y.sum())
    print(f"auc={auc(fpr, tpr):.4f} recall@0.5={(p[y == 1] >= 0.5).mean():.4f} "
          f"recall@0.90={(p[y == 1] >= 0.90).mean():.4f} (mal={n_mal}, "
          f"normal={len(y) - n_mal})")


if __name__ == "__main__":
    main()
