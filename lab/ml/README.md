# ML 恶意流量检测实验（Transformer）

用 TFLab 的 59 种工具抓包 + 补充的多样化正常流量，训练一个小型 Transformer
流分类器，重点评估 **recall（含未见过的工具）**。

## 数据

| 类别 | 数量 |
|---|---|
| 恶意流（59 工具 + 变体，65 个来源） | 465 |
| 正常流（8 种模式 × 150 + 原 normal 场景） | 1202 |

正常流特意包含**容易误判成 beacon 的良性流量**：聊天轮询(8-15s)、IoT 遥测
(20-30s)、SSH 保活(15-60s)、视频流/下载/浏览/API/DNS，避免模型用
"周期性=恶意"作弊。

## 流序列特征

每条流转成一个 token 序列（最多 96 事件）+ 流级特征：

- **事件序列**（按时间排序的载荷事件）：方向(2) + 大小 log2 分桶(32) +
  到达间隔分桶(12) → 三类 embedding 求和
- **流级特征(7)**：是否 TLS、是否带 SNI、时长、上行/下行字节、事件数、
  目的端口（全部归一化）——**不含 SNI 具体值**，避免模型背域名
- **跨流上下文特征(2)**：同源→同目的端口 10s 窗口内连接数（burst）、
  同源→同目的 10s 窗口内探测的不同端口数（sweep）——让单流分类器能看到
  "大量短连接打同一端口/扫一片端口"这种**跨流**信号（爆破/扫描检测的关键）
- **无载荷连接**（SYN 探测）：保留为"零数据事件"，不再被过滤

## 模型

`FlowTransformer`：2 层 TransformerEncoder（d=64, 4 头, FF=128）+ CLS 池化
→ 二分类。BCE + label smoothing(0.1)，AdamW 1e-3，40 epoch 早停。

## 评估（两种分割）

### A. 随机分割（in-distribution）

| 阈值 | recall | precision | F1 | specificity | AUROC | AUPRC |
|---|---|---|---|---|---|---|
| 0.5 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |

29 个测试工具召回全部 ≥0.8（实际全 1.0）。

### B. 按工具留出（13 个完全未见过的工具）

训练时完全剔除 13 个工具（abptts/aptc68/close/evilox/gost/lazarus/
metasploit/oceanlotus/rakshasa/silenttrinity/sparkrat/tristealer/xiebro），
normal 按 70/15/15 分入训练/验证/测试。

| 阈值 | recall | precision | F1 | specificity | AUROC | AUPRC |
|---|---|---|---|---|---|---|
| 0.5 | 0.990 | 0.995 | 0.993 | 0.994 | 0.998 | 0.999 |
| Youden(0.56) | 0.990 | 0.995 | 0.993 | 0.994 | 0.998 | 0.999 |

未见工具逐工具召回：11/13 个 100%，abptts 96%（25 中 24），rakshasa 0/1
（测试集仅 1 条流）。正常流量 180/181（仅 1 误报）。

## 关键方法论点

1. **去掉 SNI 身份特征**：最初版本带 SNI 分桶，随机分割直接"背域名"达到
   完美分——按工具留出才暴露真实泛化能力。
2. **label smoothing 抑制饱和**：无平滑时 logit 无界、sigmoid 全饱和到
   0.997，0.5 阈值下把所有流量判恶意；平滑后校准正常。
3. **验证集必须有负样本**：早期场景分割把 normal 全放测试集，验证集只有
   恶意流，阈值无从调。

## 爆破/扫描检测（重训后）

在训练集中加入 SSH 爆破(900)、HTTP 登录爆破(900)、SYN 端口扫描(3000) 三种
行为流量（共 4800 流），并补上跨流上下文特征后重训：

| 场景 | 恶意 recall | 正常 FPR |
|---|---|---|
| C1 同分布留出 30% | **1.000** | 0.000 |
| C2 跨模式：未见 SYN 扫描（3000 流全留出） | **1.000** | 0.000 |
| C3 跨模式：未见 SSH 爆破（900 流全留出） | **1.000** | 0.006 |
| C4 跨模式：未见 HTTP 爆破（900 流全留出） | **1.000** | 0.006 |

推理验证（保存的模型直接跑三种 pcap）：SSH 爆破 900/900、HTTP 爆破 900/900、
SYN 扫描 3000/3000 全部判恶意；正常浏览/API/聊天/IoT 0/150 零误报。

> 旧模型（无跨流特征、无爆破样本）对 SSH 爆破 0/900 漏检、SYN 扫描不可见；
> 说明检测爆破/扫描必须看到**跨流聚合**，单条流形状本身不够。

## 复现

```bash
cd lab
# 1. 环境（python3.12 + torch + sklearn）
/opt/homebrew/bin/python3.12 -m venv ml/.venv && ml/.venv/bin/pip install torch scikit-learn numpy
# 2. 生成多样化正常流量（8 模式 × 150 流）
python3 ml/gen_normal.py 150
# 3. 构建数据集
ml/.venv/bin/python ml/build_dataset.py
# 4. 训练 + 评估（输出 reports/report.json + 控制台表格）
ml/.venv/bin/python ml/train_transformer.py
```

产物：`ml/data/dataset.pt`（6558 流）、`ml/reports/report.json`、
`ml/reports/flow_transformer.pt`。
