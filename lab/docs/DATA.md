# TFLab 数据说明（Data Catalog）

> 更新：2026-08-13（参数化重跑后）｜ 数据文件：`ml/data/dataset.pt`
> ｜ 构建脚本：`ml/build_dataset.py` ｜ 抓包目录：`data/captures/`

本文档说明训练集里每一类流量的**来源与生成方式**。工具指纹的详细解读见
[TOOL_INDEX.md](TOOL_INDEX.md)，每个攻击的"是什么/为什么/怎么做"讲解见
`web/src/attacks.js`，每个工具场景的声明见 `scenarios/<tool>/scenario.json`。

## 1. 数据集概览

| 项 | 值 |
|---|---:|
| 总流数 | 14,252 |
| 恶意 | 5,827 |
| 正常 | 8,425 |
| 恶意标签数 | 67（59 个集成工具 + 4 个爆破来源 + 4 个补充行为标签） |
| 每流特征 | 73 维 meta（16 行为 + 39 CIC + HTTP 7 + 多尺度 11）+ 事件序列（≤96 事件）+ 标签/工具/来源 |

恶意构成：

| 组成 | 标签 | 流数 |
|---|---:|---:|
| 59 个集成工具（含 39 个稀有工具的 3 轮参数化重跑） | 59 | 934 |
| 爆破/扫描（4 类） | bruteforce_scan / bruteforce_ssh / bruteforce_http / bruteforce | 4,880 |
| 补充行为标签（连接关闭/保活等早期场景） | close / keepalive / sish2 / st4 | 13 |

正常构成：

| 来源 | 流数 |
|---|---:|
| 本机真实捕获（`real_traffic{1-5}`/`_sr{,2}`/`wenxin`/`kefei` 等） | 3,021 |
| 合成正常场景 `data/captures/normal_*.pcap`（17 个） | 5,400 |
| 早期正常捕获 `data/captures/cap_normal.pcap` | 4 |

### 1.1 稀有工具参数化重跑（2026-08-13）

针对原数据集中流数 ≤5 的 39 个工具，每个重跑 3 轮场景并注入随机种子：

- beacon 驱动工具：`beacon_agent.py --seed <随机>`，每轮随机化载荷大小与心跳抖动；
- 真二进制场景：保留工具自带的原生随机性（加密填充 / 周期抖动 / 重连退避）；
- 产出：`data/captures/rounds/<tool>/cap_r{0..3}.pcap`（r0 = 原始抓包备份，
  r1-r3 = 三轮新抓包）；批跑脚本：`scripts/rerun_rare_tools.sh`；
- 效果：59 个工具从 460 流增至 934 流；流数 ≤5 的工具从 39 个降到 17 个。

## 2. 特征提取管线（简述）

`ml/build_dataset.py` 从每个 pcap 提取五元组流（去重），然后：

1. **行为特征 16 维**（`flow_meta`）：is_tls、has_sni、tls13、duration、总上行/下行字节、
   事件数、dport、跨流特征（same_port_burst / ports_sweep / distinct_dsts）、
   ClientHello/ServerHello 长度、请求响应比、最大记录、estab 等；
2. **CIC 特征 39 维**（`cic_features`）：包数/字节、双向包长 min/max/mean/std、
   双向 IAT、流 IAT、TCP 标志计数、down/up 比、active/idle 统计（log1p 归一）；
3. **事件序列**（≤96 事件）：方向（C→S / S→C）+ 载荷大小 bucket + 间隔 bucket；
4. **跨流特征**：同源近端窗口内的 `same_port_burst`、`ports_sweep`、`distinct_dsts_recent`，
   用于识别"一台机器短时间内发起大量短连接"的爆破/扫描形态。

## 3. 恶意流量

### 3.1 爆破 / 扫描（4,880 流）

| 标签 | 流数 | 来源 | 形态 |
|---|---:|---|---|
| bruteforce_scan | 3,000 | `framework/bench/gen_bruteforce.py`（scan_syn 模式） | TCP SYN sweep：一个源对大量不同端口只发 SYN，无载荷 |
| bruteforce_ssh | 900 | 同上（bf_ssh 模式） | SSH 爆破：大量到 :22 的短会话，banner/认证小载荷 |
| bruteforce_http | 900 | 同上（bf_http 模式） | HTTP 登录爆破：大量到 :8080 的 POST /login 短流 |
| bruteforce | 80 | `scenarios/bruteforce/run.sh`（真实 socket 脚本） | 单源对同一端口 2222 快速发起 80 次短连接（8s 内） |

三种合成爆破模式均带固定随机种子（`random.seed(20260812)`），可精确复现。

### 3.2 集成工具（59 个，460 流）

生成体系分三类：

- **真实工具流量**：在 Docker 场景（`scenarios/<tool>/run.sh`）里跑真实二进制/官方客户端，
  tcpdump 抓成 `data/captures/cap_<tool>.pcap`。例如 behinder（真实 Behinder.jar + Tomcat JSP）、
  godzilla、cobaltstrike（geacon + teamserver）、covenant（真实 grunt）、
  mythic（真实 Athena agent）、deimos（真实 TCP agent）、xiebro（真实 Linux client）、
  sish（真实 server）、ngrok（真实 arm64 agent）、abptts（原版 Python2 客户端）、
  metasploit（meterpreter）、sliver、merlin、ligolo、frp、platypus、suo5、shadowtls。
- **协议驱动仿真**：对仅 Windows / 闭源、本环境无法跑真实 agent 的工具，按官方协议
  实现仿真客户端（`framework/drivers/`），例如 silenttrinity、evilox、octopus、nimplant、
  bruteratel、adaptix、rakshasa、vshell、antsword（官方 core 协议）、chopper（z0/z1）、
  remcos、sparkrat、ksrat、loki、zloader、tristealer、rustystealer、ktlvdoor、wmrat、
  badnews、perfspyrat、fatalrat、simayrat、yinhu、manlinghua、oceanlotus、sidewinder、
  transparenttribe、aptc60、aptc68、hemao、lazarus、apt29、oilrig、donot、ghostwriter、
  vagent。
- **行为仿真**：按公开协议特征构造纯流量形态，如 gost（ws 中继 + 周期性短流）、
  stowaway（AES-256-GCM 帧格式）等。

各工具流数与流量形态（指纹一句话，详见 TOOL_INDEX）：

| 类别 | 工具 | 流数 | 形态 |
|---|---|---:|---|
| webshell | 冰蝎 Behinder | 9 | TLS 加密；一操作一连接，13±3 条记录，请求侧恒定 8225B 分块 |
| webshell | 哥斯拉 Godzilla | 3 | 非 TLS HTTP；首条 53KB 上传，后续 406B XOR+base64 POST |
| webshell | 蚁剑 AntSword | 5 | 非 TLS HTTP；pwd=@eval(@base64_decode(...)) + 1.8KB base64 代码 |
| webshell | 菜刀 Chopper | 10 | 非 TLS HTTP POST 短流；固定字段 z0/z1 + base64 eval |
| webshell | Weevely | 12 | 非 TLS；同端点重复短 HTTP 流，命令节奏 2-30s |
| webshell | Vagent 内存马 | 1 | HTTPS 长连接；15s±20% 心跳，固定 SNI |
| c2 | Cobalt Strike | 15 | 非 TLS HTTP 短流；GET /load + 超长 Cookie RSA metadata |
| c2 | Merlin | 5 | HTTPS/h2 周期 checkin 30s±3s；JWE 加密载荷 |
| c2 | Covenant | 4 | 非 TLS HTTP POST；i=<32hex>&data=<base64 JSON>，Chrome41 UA |
| c2 | Mythic | 1 | 非 TLS HTTP 长连接；GET /index?q=<长 base64>，~10s 周期 |
| c2 | SILENTTRINITY | 1 | HTTPS 长连接 gRPC/HTTP2+mTLS 形态；10s±10% 周期 |
| c2 | EvilOSX | 5 | HTTPS 周期 checkin 20s±20%；JXA 载荷，macOS Safari UA |
| c2 | Octopus | 6 | 非 TLS HTTP beacon 15s±20%；POST /api/v1/beacon |
| c2 | NimPlant | 5 | HTTPS beacon 短流；固定 SNI；POST /api/init |
| c2 | DeimosC2 | 11 | 非 TLS TCP；8B 长度+256B RSA-OAEP+AES-CBC；15s 周期 |
| c2 | Brute Ratel C4 | 4 | HTTPS POST beacon 短流；固定 SNI；20s±15% 周期 |
| c2 | Platypus | 6 | TLS 长连接；注册后周期 RPC 小交换 |
| c2 | Xiebro | 1 | 非 TLS 长连接；每 15s [4B 长度][48B AES-ECB] 心跳 |
| c2 | AdaptixC2 | 9 | 非 TLS HTTP 短流；POST /checkin + RC4；8s±20% |
| c2 | Vshell | 1 | TCP 长连接；10s 固定心跳小包；VKey 认证 |
| c2 | Metasploit | 118 | meterpreter https：同端点短 TLS 连接突发（10s 内 15+ 条） |
| c2 | Sliver | 1 | mTLS 长连接；beacon ~30s±抖动 |
| tunnel | Ligolo-ng | 3 | TLS1.3 AES-128-GCM；双向 29B 心跳 30s/60s |
| tunnel | Stowaway | 1 | 非 TLS；16B AuthToken；36B 头+AES-256-GCM 帧 |
| tunnel | frp | 1 | TLS 长连接；固定 30s 心跳（29B 小记录） |
| tunnel | Gost | 7 | ws 中继；同源同目标周期性短流（<1s） |
| tunnel | Ngrok | 6 | TLS；固定 SNI；指数退避重连（0.5/1/2/4s） |
| tunnel | natpass | 1 | 非 TLS；Protobuf 握手 + 周期 keepalive |
| tunnel | suo5 | 11 | JA3 随机化；5s 心跳；二进制流 POST |
| tunnel | ABPTTS | 27 | 非 TLS HTTP；随机 accessKey + AES-CBC 参数 |
| tunnel | Shadow-TLS | 8 | TLS 伪装：小 CH + 固定大小 app-data 记录 |
| tunnel | sish | 1 | SSH 反向隧道长连接；每 5s 28/52B 保活 |
| tunnel | Rakshasa | 1 | TCP 长连接；固定帧头 RAKS；20s±15% keepalive |
| rat | Remcos | 1 | TCP 长连接；REMC 帧头 + RC4/XOR；12s±15% 心跳 |
| rat | SparkRat | 6 | HTTP 周期上线 10s±20%；POST /spark/check |
| rat | KSRAT | 5 | HTTP POST 20s±15%；自定义加密；/ks/login |
| rat | Loki | 5 | HTTP 周期回连短流 15s±20%；POST /loki/status |
| rat | Zloader | 5 | HTTPS 周期 C2 15s±20%；响应>请求；固定 SNI |
| rat | TriStealer | 15 | 非 TLS HTTP POST 短突发；上行 2.5-4KB，无心跳 |
| rat | RustyStealer | 12 | HTTPS POST 短突发；上行 3-5KB；固定 SNI |
| rat | KTLVdoor | 1 | TCP 长连接；KTLV 帧头；15s±15% 心跳 |
| rat | wmRAT | 6 | HTTP POST 12s±20%；3DES 加密；/wm/update |
| rat | BADNEWS | 5 | HTTP 20s±15%；加密载荷；/news/check |
| rat | PerfSpyRAT | 6 | HTTP 10s±20%；短流节奏固定；/perf/report |
| rat | FatalRAT | 5 | HTTP 短流 12s±15%；POST /fatal/check |
| rat | SiMayRAT | 4 | HTTPS 借道云文档；15s±10% 轮询；固定 SNI |
| rat | 银狐 yinhu | 1 | UDP 周期 48B 小包暗道 8s±20% + HTTPS 双通道 |
| apt | 蔓灵花 manlinghua | 13 | 多阶段：HTTP 投递突发 + HTTPS 长连接 C2 12s±10% |
| apt | 海莲花 oceanlotus | 4 | HTTPS 远控回连；固定 SNI/UA；20s±20% |
| apt | 响尾蛇 sidewinder | 13 | 多阶段：HTTP 下载突发 + HTTPS C2 短流 12s±10% |
| apt | 摩诃草 transparenttribe | 7 | HTTPS 借道 Telegram 风格 API；GET /bot<token> 10s±10% |
| apt | 伪猎者 APT-C-60 | 5 | 借道云盘 HTTPS；20s±20% 轮询；固定 SNI |
| apt | 寄生虫 APT-C-68 | 5 | 多阶段投递 + HTTPS 回连 15s±20% |
| apt | 黑猫 hemao | 5 | HTTPS 加密回连 15s±15%；固定 SNI |
| apt | Lazarus | 4 | HTTPS C2 回连 25s±30%；beacon 周期+抖动 |
| apt | APT29 | 5 | beacon 型 HTTPS 回连 20s±25% |
| apt | OilRig | 5 | HTTP 周期回连 18s±20%；POST /ps/run |
| apt | Donot | 13 | 多阶段 HTTP(S)；RC4 载荷；C2 HTTPS 14s±10% |
| apt | Ghostwriter | 4 | 借道云存储 HTTPS；22s±20% 轮询；固定 SNI |

补充行为标签（早期场景运行产物，流数少）：

| 标签 | 流数 | 说明 |
|---|---:|---|
| close | 10 | 连接关闭行为补充样本 |
| keepalive | 1 | 长连接保活行为补充样本 |
| sish2 | 1 | sish 第二次运行变体 |
| st4 | 1 | 隧道/转发补充运行变体 |

> 说明：`data/` 下的 cap_st2/cap_st3/cap_gost2 抓包为空（0 流），未进入数据集；
> cap_real_negative.pcap 是真实流量子集，作为正常数据使用（见 4.1）。

## 4. 正常流量

### 4.1 本机真实捕获（1,471 流）

来源：`data/captures/real_traffic.pcap`（185）、`real_traffic2.pcap`（320）、`real_traffic3.pcap`（330）、
`real_traffic4.pcap`（636），为本机日常使用期间抓包（浏览器/TLS、DNS、mDNS、系统同步、
API 调用、长连接传输等）。形态统计：

| 指标 | 值 |
|---|---:|
| TLS / SNI 占比 | 46% / 42% |
| 目标端口 Top | 443（492）、53（144）、5353 mDNS（145）、80（20） |
| 流时长 | 中位 4.2s，p95 207s（含长连接长尾） |
| 字节数 | 上行中位 1.9KB，下行中位 864B |
| 事件数 | 中位 11 |

这 4 个 pcap 已并入 `build_dataset.py` 的 normal 列表参与训练，用于压低真实流量误报
（含微信 mmtls 这类短 HTTP 边界样本）。

### 4.2 合成正常场景（5,400 流）

生成器：`ml/gen_normal.py`，输出 `data/captures/normal_*.pcap`。覆盖两类：

**a) 日常正常形态**：

| 场景 | 流数 | 模拟内容 |
|---|---:|---|
| normal_browse | 150 | 浏览器 TLS 页面浏览（300-500B 请求 / 1-30KB 响应） |
| normal_api | 150 | API 短请求（TLS 443，100-800B） |
| normal_stream | 150 | 长流媒体 TLS 连接（30-60 个 1-8KB 数据块） |
| normal_download | 150 | 大文件下载（20-60 个 1448B 满包） |
| normal_chat | 150 | 消息轮询：8-15s 一次 TLS 短轮询（良性但像 beacon） |
| normal_iot | 150 | 设备遥测：20-30s 一次 80B POST（良性但像 beacon） |
| normal_ssh | 150 | 正常 SSH 会话（200-600B 握手 + 周期小包） |
| normal_dns | 150 | 常规 DNS 查询（3-6 条） |

**b) 合法但像探测/爆破的难负样本**（单源大量短连接，用于压爆破检测误报）：

| 场景 | 流数 | 模拟内容 |
|---|---:|---|
| normal_healthcheck | 640 | 监控服务器（Zabbix/Nagios 风格）对 8 台主机每 20-40s 一次 GET /health |
| normal_crawler | 800 | 爬虫对单主机每 0.15-0.5s 一次 GET（40 连/轮） |
| normal_browser_burst | 600 | 浏览器加载页面：30 条短 TLS 连接突发 |
| normal_dns_storm | 1,000 | DNS 解析风暴：50 条/轮，0.02-0.2s 间隔 |
| normal_sync_burst | 360 | 后台同步 App 对单一端点反复开短 TLS 连接（像 beacon 但合法） |
| normal_failed_conn | 240 | 正常连接失败：SYN-only / SYN→RST（零载荷） |
| normal_flaky_ssh | 160 | 网络不稳的 SSH 重连：约 8 次/4 分钟指数退避 |
| normal_short_http | 200 | 健康检查/API ping：GET /ping 短 HTTP |
| normal_udp_app | 200 | 小型 UDP 应用探测/保活（高位端口） |

### 4.3 早期正常捕获（4 流）

`data/captures/cap_normal.pcap`：早期场景框架跑的正常基线抓包，仅 4 流。

## 5. 正常流量数值快照（数据集内 6,875 流）

| 指标 | 值 |
|---|---:|
| TLS / SNI 占比 | 34.7% / 34.0% |
| 已建立连接占比 | 94.9% |
| dport 分布 | 443（30%）、高位端口（21%）、80（21%）、53（19%）、特权端口（5%）、5353（2%） |
| 流时长（log1p） | 中位 0.010（约 10ms），p95 4.77（约 118s） |
| 上行字节（log1p） | 中位 4.33（约 75B），p95 8.22（约 3.7KB） |
| 下行字节（log1p） | 中位 6.29（约 540B），p95 10.86（约 52KB） |
| 事件数（log1p） | 中位 1.10（约 2 事件），p95 3.69（约 39 事件） |

## 6. 复现 / 重建命令

```bash
# 合成正常流量（17 个场景）
python3 ml/gen_normal.py

# 合成爆破/扫描流量（scan_syn / bf_ssh / bf_http）
python3 framework/bench/gen_bruteforce.py data/

# 工具场景流量（每个工具的 run.sh + scenario.json，由 harness 调度）
bash framework/harness/run_scenario.sh <tool>

# 重建数据集（读取 data/ 下全部 pcap，产出 dataset.pt）
python3 ml/build_dataset.py
```
