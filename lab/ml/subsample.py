#!/usr/bin/env python3
"""Subsample a dataset.pt by flow count per (tool, label) group.

Usage: python3 ml/subsample.py <frac> <in.pt> <out.pt>
Keeps at least one flow per group so the tool set is preserved.
"""

import sys

import numpy as np
import torch


def main():
    frac = float(sys.argv[1])
    src, dst = sys.argv[2], sys.argv[3]
    d = torch.load(src, weights_only=False)
    tools = d["tools"]
    groups = {}
    for i, t in enumerate(tools):
        groups.setdefault(t, []).append(i)
    rng = np.random.RandomState(0)
    sel = []
    for t, idxs in groups.items():
        idxs = np.asarray(idxs)
        rng.shuffle(idxs)
        k = max(1, int(round(len(idxs) * frac)))
        sel.extend(idxs[:k].tolist())
    sel = torch.from_numpy(np.sort(np.asarray(sel)))
    keys = [k for k in d
            if k in ("X_dir", "X_sz", "X_dt", "X_mask", "X_meta",
                     "X_int_flow", "X_int_cross", "y", "tools", "origins")]
    for k in keys:
        if isinstance(d[k], torch.Tensor):
            d[k] = d[k][sel]
        else:
            d[k] = [d[k][i] for i in sel.tolist()]
    torch.save(d, dst)
    mal = int(d["y"].sum())
    print(f"frac={frac}: {len(d['y'])} flows (mal {mal} / norm "
          f"{len(d['y']) - mal}), groups={len(groups)} -> {dst}")


if __name__ == "__main__":
    main()
