#!/usr/bin/env python3
"""Five-type architecture (additive; existing models are untouched).

Five feature types -> three tokenizers -> simple per-type pooling fusion:
  FlowDense(48)  -> 7 DCN-V2 groups     -> 7 tokens
  CrossDense(10) -> 3 DCN-V2 groups     -> 3 tokens
  FlowInt(9)     -> GroupNSTokenizer    -> 2 tokens
  CrossInt(4)    -> GroupNSTokenizer    -> 2 tokens
  FlowSequence   -> UserBehavior (Transformer Encoder) -> 1 token

Fusion: mean-pool per type -> concat(5 x 64 = 320) -> LayerNorm -> MLP head.
"""

import os
import sys

import numpy as np
import torch
import torch.nn as nn

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import build_dataset as B  # noqa: E402
from train_transformer import DCNGroup  # noqa: E402


FIVE_FD_GROUPS = [
    [3, 4, 5, 6],                 # G1 规模
    [7, 10, 11, 12, 13],          # G2 TLS/端口
    [16, 17, 18, 19, 20],         # G3 CIC 基础
    list(range(21, 29)),          # G4 CIC 包长
    list(range(29, 41)),          # G5 CIC IAT (12)
    list(range(41, 47)),          # G6 CIC 标志/方向 (6)
    list(range(47, 55)),          # G7 CIC 活跃/空闲 (8)
]
FIVE_CD_GROUPS = [
    [8, 9, 15],                   # C1 10s 跨流
    [63, 64, 66, 67, 69, 70],     # C2 多尺度比率
    [72],                         # C3 源级失败率
]
FIVE_FLOW_INT_VOCAB = [2, 2, 2, 2, 2, 2, 2, 2, 6]
FIVE_CROSS_INT_VOCAB = [16, 16, 16, 16]
FIVE_FLOW_INT_GROUP_IDS = [0, 0, 0, 0, 1, 1, 1, 1, 1]   # I1 TLS/会话, I2 HTTP
FIVE_CROSS_INT_GROUP_IDS = [0, 0, 0, 1]                  # CI1 突发, CI2 源级端口


class GroupNSTokenizer(nn.Module):
    """Per-feature embedding tables grouped by semantics; group-sum -> token."""
    def __init__(self, vocab_sizes, group_ids, embed_dim=16, d_model=64):
        super().__init__()
        self.embs = nn.ModuleList(
            [nn.Embedding(v, embed_dim) for v in vocab_sizes])
        self.group_ids = group_ids
        self.n_groups = max(group_ids) + 1
        self.proj = nn.Linear(embed_dim, d_model)

    def forward(self, x):
        e = torch.stack([emb(x[:, i]) for i, emb in enumerate(self.embs)], dim=1)
        toks = []
        for g in range(self.n_groups):
            idx = [i for i, gi in enumerate(self.group_ids) if gi == g]
            toks.append(self.proj(e[:, idx].sum(dim=1)))
        return torch.stack(toks, dim=1)  # B, n_groups, d_model


class FlowTransformerFive(nn.Module):
    def __init__(self, d_model=64, nhead=4, layers=2, ff=128, dropout=0.1,
                 embed_dim=16, inner_attn=True, cross_attn=True,
                 attn_mode="replace", dual_cls=None, slim=False,
                 head_mode="mlp", dual_head=False,
                 branch_mask=(True, True, True, True)):
        # attn_mode: "replace" (attention output only, default for back-compat)
        #            "residual" (direct_pool + attended_pool per branch)
        #            "concat"   (per-branch [direct, attended] concatenated)
        # dual_cls: None (off) | "post" (add Linear+DCN to CLS after encoder)
        #          | "pre" (inject into CLS before encoder, like dual)
        super().__init__()
        self.dir_emb = nn.Embedding(2, d_model)
        self.sz_emb = nn.Embedding(32, d_model)
        self.dt_emb = nn.Embedding(12, d_model)
        self.pos = nn.Parameter(torch.randn(1, B.MAX_LEN + 1, d_model) * 0.02)
        self.cls = nn.Parameter(torch.randn(d_model) * 0.02)
        if dual_cls:
            self.meta_proj = nn.Linear(73, d_model)
            self.dcn_proj = DCNGroup(73, d_model)
        else:
            self.meta_proj = None
            self.dcn_proj = None
        self.dual_cls = dual_cls
        self.branch_mask = list(branch_mask)  # [fd, cd, fi, ci]
        def make_groups(groups):
            mods = []
            for g in groups:
                if slim and len(g) <= 6:
                    mods.append(nn.Sequential(
                        nn.Linear(len(g), d_model), nn.GELU()))
                else:
                    mods.append(DCNGroup(len(g), d_model))
            return nn.ModuleList(mods)
        self.fd_groups = (make_groups(FIVE_FD_GROUPS)
                          if branch_mask[0] else None)
        self.cd_groups = (make_groups(FIVE_CD_GROUPS)
                          if branch_mask[1] else None)
        self.groupns_flow = (GroupNSTokenizer(
            FIVE_FLOW_INT_VOCAB, FIVE_FLOW_INT_GROUP_IDS,
            embed_dim=embed_dim, d_model=d_model)
            if branch_mask[2] else None)
        self.groupns_cross = (GroupNSTokenizer(
            FIVE_CROSS_INT_VOCAB, FIVE_CROSS_INT_GROUP_IDS,
            embed_dim=embed_dim, d_model=d_model)
            if branch_mask[3] else None)
        n_branch = sum(self.branch_mask)
        enc = nn.TransformerEncoderLayer(
            d_model=d_model, nhead=nhead, dim_feedforward=ff,
            dropout=dropout, batch_first=True, activation="gelu")
        self.enc = nn.TransformerEncoder(enc, num_layers=layers)
        # stage 1: intra-branch self-attention (shared layer over each
        # non-sequence branch's tokens)
        self.inner_attn = (nn.TransformerEncoderLayer(
            d_model=d_model, nhead=nhead, dim_feedforward=ff,
            dropout=dropout, batch_first=True, activation="gelu")
            if inner_attn else None)
        # stage 2: inter-branch cross-attention over all tokens
        self.cross_attn = (nn.TransformerEncoderLayer(
            d_model=d_model, nhead=nhead, dim_feedforward=ff,
            dropout=dropout, batch_first=True, activation="gelu")
            if cross_attn else None)
        self.fusion_norm = nn.LayerNorm((1 + n_branch) * d_model)
        if head_mode == "linear":
            self.five_head = nn.Sequential(
                nn.LayerNorm((1 + n_branch) * d_model),
                nn.Linear((1 + n_branch) * d_model, 1))
        elif head_mode == "mlp_ln":
            self.five_head = nn.Sequential(
                nn.Linear((1 + n_branch) * d_model, 128), nn.GELU(),
                nn.Dropout(dropout),
                nn.LayerNorm(128), nn.Linear(128, 1))
        else:
            self.five_head = nn.Sequential(
                nn.Linear((1 + n_branch) * d_model, 128), nn.GELU(),
                nn.Dropout(dropout),
                nn.Linear(128, 1))
        self.head_mode = head_mode
        # dual-style head on the dual-enriched CLS; logits are summed with the
        # five fusion head (learned additive ensemble).
        if dual_head:
            self.dual_head = nn.Sequential(
                nn.LayerNorm(d_model), nn.Linear(d_model, 1))
        else:
            self.dual_head = None
        self.dual_head_flag = dual_head
        self.attn_mode = attn_mode
        if attn_mode == "concat":
            self.concat_norm = nn.LayerNorm(10 * d_model)
            self.concat_head = nn.Sequential(
                nn.Linear(10 * d_model, 128), nn.GELU(), nn.Dropout(dropout),
                nn.Linear(128, 1))

    def forward(self, X_dir, X_sz, X_dt, X_mask, X_meta,
                X_int_flow, X_int_cross):
        Bn, L = X_dir.shape
        ev = self.dir_emb(X_dir) + self.sz_emb(X_sz) + self.dt_emb(X_dt)
        cls = self.cls.unsqueeze(0).expand(Bn, -1)
        if self.dual_cls == "pre":
            cls = cls + self.meta_proj(X_meta) + self.dcn_proj(X_meta)
        seq = torch.cat([cls.unsqueeze(1), ev], dim=1)
        seq = seq + self.pos[:, :seq.size(1)]
        pad = torch.cat(
            [torch.zeros(Bn, 1, device=X_mask.device), X_mask], dim=1)
        beh = self.enc(seq, src_key_padding_mask=pad.bool())[:, 0]
        if self.dual_cls == "post":
            beh = beh + self.meta_proj(X_meta) + self.dcn_proj(X_meta)
        # branch tokens (enabled only), insertion-ordered: fd, cd, fi, ci
        toks = {}
        if self.fd_groups is not None:
            toks["fd"] = torch.stack(
                [g(X_meta[:, idx])
                 for g, idx in zip(self.fd_groups, FIVE_FD_GROUPS)], dim=1)
        if self.cd_groups is not None:
            toks["cd"] = torch.stack(
                [g(X_meta[:, idx])
                 for g, idx in zip(self.cd_groups, FIVE_CD_GROUPS)], dim=1)
        if self.groupns_flow is not None:
            toks["fi"] = self.groupns_flow(X_int_flow)
        if self.groupns_cross is not None:
            toks["ci"] = self.groupns_cross(X_int_cross)
        dirs = {k: v.mean(dim=1) for k, v in toks.items()}  # direct reads
        # stage 1: intra-branch interaction
        if self.inner_attn is not None:
            for k in toks:
                toks[k] = self.inner_attn(toks[k])
        # stage 2: inter-branch cross-attention over enabled tokens + CLS
        all_tok = torch.cat([beh.unsqueeze(1)] + [toks[k] for k in toks], dim=1)
        if self.cross_attn is not None:
            all_tok = self.cross_attn(all_tok)
        beh2 = all_tok[:, 0]
        off = 1
        att = {}
        for k in toks:
            n = toks[k].shape[1]
            att[k] = all_tok[:, off:off + n].mean(dim=1)
            off += n
        # stage 3: per-branch pooling + fusion
        if self.attn_mode == "replace":
            f = torch.stack([beh2] + [att[k] for k in toks], dim=1)
            five_logit = self.five_head(self.fusion_norm(f.flatten(1))).squeeze(-1)
        elif self.attn_mode == "residual":
            f = torch.stack([beh + beh2] + [dirs[k] + att[k] for k in toks],
                            dim=1)
            five_logit = self.five_head(self.fusion_norm(f.flatten(1))).squeeze(-1)
        else:  # concat
            f = torch.cat([beh, beh2] +
                          [v for k in toks for v in (dirs[k], att[k])], dim=1)
            five_logit = self.concat_head(self.concat_norm(f)).squeeze(-1)
        if self.dual_head is not None:
            five_logit = five_logit + self.dual_head(beh).squeeze(-1)
        return five_logit


def flows_to_tensors_five(flows):
    """Same as predict_pcap.flows_to_tensors, plus integer feature tensors."""
    metas = [B.all_meta(c) for c in flows]
    B.cross_flow_meta(flows, metas)
    fi, ci = B.int_feature_arrays(metas)
    X_dir, X_sz, X_dt, X_mask = [], [], [], []
    for c in flows:
        evs = B.events_of(c)[:B.MAX_LEN]
        n = len(evs)
        X_dir.append([e[0] for e in evs])
        X_sz.append([B.size_bucket(e[1]) for e in evs])
        X_dt.append([B.dt_bucket(e[2]) for e in evs])
        X_mask.append([1.0] * n)
    if not X_dir:
        return None
    n = len(X_dir)
    ad = np.zeros((n, B.MAX_LEN), dtype=np.int64)
    az = np.zeros((n, B.MAX_LEN), dtype=np.int64)
    at = np.zeros((n, B.MAX_LEN), dtype=np.int64)
    am = np.zeros((n, B.MAX_LEN), dtype=np.float32)
    for i in range(n):
        ln = len(X_dir[i])
        ad[i, :ln] = X_dir[i]
        az[i, :ln] = X_sz[i]
        at[i, :ln] = X_dt[i]
        am[i, :ln] = X_mask[i]
    return {
        "X_dir": torch.from_numpy(ad).long(),
        "X_sz": torch.from_numpy(az).long(),
        "X_dt": torch.from_numpy(at).long(),
        "X_mask": torch.from_numpy(am).float(),
        "X_meta": torch.from_numpy(np.asarray(metas, dtype=np.float32)),
        "X_int_flow": torch.from_numpy(fi).long(),
        "X_int_cross": torch.from_numpy(ci).long(),
    }


def load_five(path, d_model=64, layers=2, inner_attn=True, cross_attn=True,
              attn_mode="replace", dual_cls=False):
    m = FlowTransformerFive(d_model=d_model, layers=layers,
                            inner_attn=inner_attn, cross_attn=cross_attn,
                            attn_mode=attn_mode, dual_cls=dual_cls)
    m.load_state_dict(torch.load(path, weights_only=True, map_location="cpu"))
    m.eval()
    return m
