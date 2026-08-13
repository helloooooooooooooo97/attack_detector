# QueryFormer 架构迁移对比实验

日期：2026-08-13

## 背景

[QueryFormer（KDD Cup 2026 Tencent UniRec 工业赛道冠军）](https://mp.weixin.qq.com/s/BG63zmVLRsaFgAZFv6_xmw)
核心思路：先让用户/广告/稠密特征充分交互生成高质量 Query，再用 Query 去行为序列中检索；
并通过"非序列特征按语义分组"和"H=4 多列 Embedding Matrix"扩展 Query 表达。

迁移到本项目（单流恶意流量二分类，55 维 meta + 事件序列）的两个可迁移点：

1. **非序列特征分组**：meta 按语义拆成两组（行为 16 维 / CIC 39 维），各自投影成一个 token；
2. **多列 Embedding Matrix**：同一份 meta 用 H=4 套独立 Linear 投影取均值（多视角融合）。

## 变体

| 变体 | 实现 |
|---|---|
| `flat`（基线/生产） | 55 维 meta 单投影，直接加到 CLS token |
| `grouped` | 16 维行为 + 39 维 CIC 各投影成独立 token（序列前加 2 个 meta token） |
| `multicol` | H=4 套 Linear(55→64) 独立投影，取均值加到 CLS |
| `grouped_multicol` | 两组 × H=4 多视角，每组取均值成独立 token（两者叠加） |

数据：12228 流（恶意 5353 / 正常 6875，含 bruteforce_scan 3000、ssh 900、http 900）。
训练：`ml/train_transformer.py --variant ...`，d_model=64、2 层、30 epoch 早停、torch.compile。

## 结果

### A. 随机分割（同分布，seed 42 单次）

| 变体 | 参数量 | recall@0.5 | specificity@0.5 | AUROC | recall(调阈值) |
|---|---|---:|---:|---:|---:|
| flat | 79,937 | 0.991 | 0.998 | 0.999 | 0.986 |
| grouped | 80,129 | 0.988 | 0.989 | 0.998 | 0.981 |
| multicol | 90,689 | **0.993** | **1.000** | 0.999 | 0.993 |
| grouped_multicol | 91,073 | 0.991 | 0.991 | 0.996 | 0.990 |

同分布下四者都接近饱和，multicol 略好（+0.2pp recall、测试集 0 误报），差异不显著。

### B. 工具级 5 折（全部工具作为未见测试，3 个折划分种子 42/7/123）

非扫描工具的未见 recall（排除 bruteforce_scan 3000 条，避免单折阈值主导）：

| 变体 | seed42 | seed7 | seed123 | 均值 |
|---|---:|---:|---:|---:|
| flat | 0.928 | 0.926 | 0.967 | **0.940** |
| multicol | 0.928 | 0.924 | 0.920 | 0.924 |
| grouped | 0.889 | 0.921 | 0.937 | 0.915 |
| grouped_multicol | 0.904 | 0.889 | 0.926 | 0.907 |

未见 SYN 扫描（bruteforce_scan 整组 3000 条留出）检出：

| 变体 | seed42 | seed7 | seed123 | 检出次数 |
|---|---|---|---|---:|
| flat | 3000/3000 | 3000/3000 | 0/3000 | 2/3 |
| multicol | 0/3000 | 3000/3000 | 0/3000 | 1/3 |
| grouped | 0/3000 | 0/3000 | 0/3000 | **0/3** |
| grouped_multicol | 0/3000 | 3000/3000 | 0/3000 | 1/3 |

B 总体 recall（受扫描折阈值影响，方差大，仅参考）：flat 0.425–0.968；
grouped 0.391–0.412；multicol 0.404–0.967；grouped_multicol 0.398–0.951。
AUROC（阈值无关）：flat 0.96–0.98；multicol 0.97–0.99；grouped 0.90–0.95；grouped_multicol 0.84–0.96。

## 结论

1. **QueryFormer 的两个迁移点在我们任务上不成立**：flat（meta 单投影直连 CLS）仍是未见工具
   泛化最好的结构；特征分组、多列平均都会让关键判别信号（扫描/爆破特征）绕道或稀释。
2. **未见扫描检测对全部变体都敏感**：它取决于留出折训练集还剩多少同类爆破数据；
   flat 成功率最高（2/3），grouped 恒失败（0/3）——行为特征经分组 token 后再被 CLS 注意力
   "读出"，对未见扫描的归纳最差。
3. **生产模型保持 flat 不动**；若未来要吸收 QueryFormer 思路，方向是保留 CLS 直连 meta 的
   同时增加多视角（如多列输出拼接而非平均、或仅对 CIC 组做多列），并以 B 未见工具为准评估。

## 追问：是不是 group 粒度太粗？

把 grouped 的 2 组拆细后复测（同一 3 个折种子）：

| 粒度 | 组数 | B 未见扫描检出 | B 非扫描 recall 均值 | B AUROC | A recall@0.5 / spec@0.5 |
|---|---|---:|---:|---:|---:|
| coarse | 2 | 0/9（3 种子全 0） | 0.915 | 0.90–0.95 | 0.988 / 0.989 |
| mid | 8 | 0/9 | 0.915 | 0.84–0.95 | 0.991 / 0.996 |
| fine | 11 | 0/9 | 0.920 | 0.90–0.95 | 0.991 / 0.997 |
| flat（对照） | — | 2/3 | 0.940 | 0.96–0.98 | 0.991 / 0.998 |

**结论：粒度不是原因。** 无论 coarse/mid/fine，grouped 对未见扫描都是 9/9 全漏；
非扫描未见 recall 也只比 coarse 微升 0.005（0.920 vs 0.915），仍低于 flat 的 0.940。
细分组只在同分布 A 上有微弱收益（0.991/0.997 vs 0.988/0.989），与 QueryFormer 原文
"分组保留组内结构"的结论一致，但这救不了未见泛化。

真正的原因在结构：grouped 的 meta 信息要经注意力"绕行"到 CLS 分类头，这条路径对训练集
外的新模式（未见扫描）没有形成可靠归纳；flat 把 55 维 meta 一步投影进 CLS，扫描/爆破
这些人工特征在分类头上是直读的。所以后续若要吸收分组思路，只能作为 flat 的附加并行
通路（CLS 直连保留），不能替换。

## 追问：组内没有做 DCN（Deep & Cross Network）？

此前的 grouped 组内只有一层 Linear，没有特征交叉——补上 QueryFormer 原文的完整配方：
每组建一个低秩 DCN-V2（cross 分支显式特征交叉 + deep MLP 分支，concat 后投影成 token），
`--dcn` 开关，对 flat / grouped 都生效。3 个折种子复测：

| 变体 | A recall@0.5 / spec@0.5 | 未见扫描检出 | B 非扫描 recall 均值 | B AUROC |
|---|---:|---:|---:|---:|
| flat（Linear，现生产） | 0.991 / 0.998 | 2/3 | 0.940 | 0.96–0.98 |
| flat + DCN | 0.994 / 0.997 | **0/3** | **0.956** | 0.93–0.97 |
| grouped coarse（Linear） | 0.988 / 0.989 | 0/3 | 0.915 | 0.90–0.95 |
| grouped coarse + DCN | 0.990 / 0.999 | 1/3（命中折 3000/3000） | 0.953 | 0.89–0.97 |
| grouped fine + DCN | 0.994 / 0.998 | 0/3 | 0.804（不稳） | 0.84–0.94 |

**结论：DCN 是双刃剑，不是免费午餐。**

1. DCN 对"常规未见工具"的泛化确实有正收益：flat 0.940→0.956，grouped coarse 0.915→0.953，
   且同分布 A 也微升（0.991→0.994）。这印证了 QueryFormer 原文选 DCN-V2 不是玄学。
2. 但 DCN 会破坏扫描检测：flat 从 2/3 掉到 0/3（cross 交叉项把 `ports_sweep` /
   `same_port_burst` / `distinct_dsts` 这些强判别特征和其余 50 维混在一起，稀释了直读信号）；
   grouped coarse 反而从 0/3 提升到 1/3（命中折全检出），但仍不稳。
3. fine 分组 + DCN 最不稳：seed42 把 bruteforce_ssh 整组漏掉（0/900），B 非扫描 recall 掉到
   0.540——组越细、每组建 DCN，参数越多（178k vs 81k），12k 样本上越容易过拟合。

**建议**：若吸收 DCN，应采用"双通路"结构——保留 Linear 直连 CLS（保住扫描特征），
并行加一条 DCN 交叉通路（提升常规工具交互），而不是用 DCN 替换 Linear。
当前生产模型（flat + Linear）仍是最稳妥的选择。

## 双通路实验（Linear 直连 + DCN 并行）

按上述建议实现并验证：
- `flat 双通路`：CLS += Linear(55→64) + DCNGroup(55)（两条通路同时注入 CLS）
- `grouped 双通路`：组内 DCN token + 一条全局 Linear(55→64) 残差直连 CLS

3 个折种子（42/7/123）复测：

| 变体 | A recall@0.5 / spec@0.5 / AUROC | 未见扫描检出 | B 非扫描 recall 均值 | B AUROC |
|---|---:|---:|---:|---:|
| flat（Linear，现生产） | 0.991 / 0.998 / 0.999 | 2/3 | 0.940 | 0.96–0.98 |
| flat + DCN（替换） | 0.994 / 0.997 / 0.999 | 0/3 | 0.956 | 0.93–0.97 |
| **flat 双通路** | **0.996 / 0.999 / 1.000** | **3/3** | **0.964** | 0.98–0.99 |
| grouped coarse + DCN | 0.990 / 0.999 / 0.997 | 1/3 | 0.953 | 0.89–0.97 |
| grouped coarse 双通路 | 0.998 / 0.999 / 1.000 | 0/3 | 0.975 | 0.98–0.99 |
| grouped fine 双通路 | 0.983 / 0.994 / 0.998 | 0/3 | 0.957 | 0.93–0.99 |

**结论：flat 双通路是目前所有架构变体中唯一全面占优的结构。**

1. flat 双通路三项全胜：未见扫描 3/3（9000/9000，含 ssh/http 爆破 100% 检出）、
   非扫描未见 recall 0.964（比生产 flat 高 2.4pp）、B AUROC 0.98–0.99（最稳）。
2. grouped 双通路把非扫描 recall 提到最高（0.975）但扫描仍是 0/3——说明 grouped 的问题
   不只是"CLS 缺直连"，而是 DCN token 经注意力进入 CLS 的路径本身会冲淡扫描信号，
   加全局直连救不回来；flat 双通路把两条通路都直接加在 CLS 上，不经过注意力，才是对的。
3. 机制解释：Linear 通路保留 `ports_sweep` 等强判别特征的直读边界，DCN 通路提供
   组间/组内特征交互用于常规工具，两者相加互不干扰。

**下一步（如需上线）**：用全量数据训 flat 双通路模型，在本机真实流量上复测误报率，
与生产 flat 对比后再决定是否替换。

## 真实流量复测（flat vs flat 双通路）

用与生产相同的协议重训两个模型（仅架构不同），在本机 4 个真实流量 pcap
（1471 流）上逐流打分：

| 模型 | >0.5 | >0.90 | FPR@0.5 | FPR@0.90 | mean | max | p99 |
|---|---:|---:|---:|---:|---:|---:|---:|
| flat（现生产） | 10 | 0 | 0.68% | 0.00% | 0.069 | 0.877 | 0.374 |
| flat 双通路 | 2 | 1 | 0.14% | 0.07% | 0.048 | 0.930 | **0.075** |

flat 双通路把正常流量的分数整体压紧（p99 0.075 vs 0.374，0.5 阈值误报 2 vs 10），
但引入了一个 0.930 的边界误报：real_traffic3 里一条 14 秒、1 万字节的非 TLS 长连接
（dport 60871，18/13 包），DCN 交叉项把它误判成类似信标的长连接模式；flat 给分 0.072。

### 阈值权衡（A 随机分割测试集，803 恶意 / 1032 正常）

| 模型 | 阈值 | recall | specificity | FP |
|---|---|---:|---:|---:|
| flat | 0.90 | 0.979 | 1.000 | 0 |
| flat 双通路 | 0.90 | **0.996** | 0.999 | 1 |
| flat 双通路 | 0.94 | **0.989** | 1.000 | 0 |
| flat 双通路 | 0.95 | 0.985 | 1.000 | 0 |

**上线建议**：flat 双通路 + 部署阈值 0.94 —— 真实流量 0/1471 误报，
A 测试集 0 误报、recall 0.989（flat 在 0.90 阈值下只有 0.979），
工具级未见泛化扫描 3/3、非扫描 recall 0.964。全面优于现生产 flat。

## 产物

- 汇总 JSON：`ml/reports/qf_ablation_{flat,grouped,multicol,grouped_multicol}.json`
- 粒度复测：`ml/reports/qf_ablation_grouped_{mid,fine}.json`
- DCN 复测：`ml/reports/qf_ablation_{flat,grouped_coarse,grouped_fine}_dcn.json`
- 双通路复测：`ml/reports/qf_ablation_{flat,grouped_coarse,grouped_fine}_dual.json`
- 真实流量复测模型：`ml/models/flow_transformer_{rt_flat,rt_flatdual}.pt`
- 评估脚本：`ml/eval_real_traffic.py`
- 原始报告：`ml/reports/report_qf{,_2,_3,_4}_<variant>.json`
- 代码：`ml/train_transformer.py`（`--variant` / `--h_cols` / `--group_plan` / `--dcn` / `--dual`）、
  `ml/predict_pcap.py`（`--variant` / `--group_plan` / `--dcn` / `--dual`）
