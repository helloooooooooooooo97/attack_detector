# 加密流量指纹实验室（TFLab）

一个**通用**的恶意工具加密流量指纹分析与检测框架。任何新工具只需新增一个
**场景模块**（场景目录 + 一个规则文件），抓包、解析、检测、验证全部复用。
当前已接入 **59 种攻击的实时检测**（60/60 场景全绿：59 个正样本 + normal 负样本零误报），
全部基于观成科技技术文章：

- 冰蝎内存马 webshell（[id=208](https://www.viewintech.com/detail?id=208)）
- Ligolo-ng 隐蔽隧道（[id=181](https://www.viewintech.com/detail?id=181)）
- suo5 HTTP 隧道（[id=162](https://www.viewintech.com/detail?id=162)）
- Merlin C2（[id=140](https://www.viewintech.com/detail?id=140)）
- Stowaway 多级代理（[id=203](https://www.viewintech.com/detail?id=203)）
- natpass 内网穿透（[id=170](https://www.viewintech.com/detail?id=170)）
- frp 反向代理（隧道类）
- Sliver C2（同类 C2 框架）
- 其余 51 个见 [docs/TOOL_INDEX.md](docs/TOOL_INDEX.md) 完整清单——
  **59 个 ✔ 全部有实验室实测指纹列**（真实工具或协议驱动仿真）

所有实验都在本地 Docker 容器内完成（回环地址），不涉及外部系统。

## 快速开始

```bash
cd lab
make build-probe          # 交叉编译 Go 探针（darwin/linux-arm64/amd64）
make scenario-behinder    # 跑单个场景（容器+抓包+探针）
make test                 # 跑全部场景 + 校验告警（PASS/FAIL 报告）
make replay-test          # 离线回放回归（用已抓 pcap，秒级）
cd web && npm install && npm run build   # 构建 React 前端
```

产物统一在 `data/`：`cap_<场景>.pcap`、`probe_<场景>.jsonl`（告警）、`<场景>.log`。

## 目录结构

详见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)：

```
lab/
├── framework/            # 通用核心（与具体工具无关）
│   ├── analyze.py        # pcap → TLS 流特征引擎
│   ├── rules.py          # Python 参考检测器（离线）
│   ├── probe/            # Go 实时探针（AF_PACKET + 规则注册表）
│   │   └── rules/        # 场景规则插件：behinder.go / ligolo.go
│   ├── harness/          # 容器实验框架（Dockerfile + 场景运行器）
│   └── drivers/          # 通用流量驱动（Java）
├── scenarios/            # 场景模块：behinder / ligolo / normal
│   └── <tool>/
│       ├── scenario.json # 元数据（端口/时长/抓包过滤/预期告警）
│       ├── run.sh        # 部署工具 + 产生流量
│       ├── expected.json # 金标准
│       └── rules/        # YARA / Suricata
├── test/test_runner.py   # 场景校验（正样本命中 / 负样本零误报）
└── docs/ARCHITECTURE.md  # 架构设计与测试设计
```

## 已接入场景与测试结果（60/60 通过）

| 场景 | 工具 | 检测特征 | 探针告警 | 状态 |
|---|---|---|---|---|
| `behinder` | 冰蝎 v4.0.7 内存马型 | 单流单操作、13±3 条 TLS 记录、8225B 恒定分块、请求>响应、短命连接 | `behinder.mem_shell_flow` / `behinder.memory_shell_aggregate` | ✅ PASS |
| `ligolo` | Ligolo-ng v0.9 | TLS 1.3 AES-128-GCM、双向 29B 心跳、30s/60s 周期、长连接 | `ligolo.tunnel_heartbeat` | ✅ PASS |
| `suo5` | suo5 v2.2 | 每次握手 JA3/密码套件随机化（同源多条流），5s 心跳 | `suo5.ja3_randomization` | ✅ PASS |
| `merlin` | Merlin v2 | HTTPS(h2) 周期 checkin（默认 30s±3s），JWE 载荷 | `merlin.polling` | ✅ PASS |
| `stowaway` | Stowaway v2.2 | 非 TLS；首包 16B AuthToken + 16B 回显；AES-256-GCM 帧 | `stowaway.auth_token_handshake` | ✅ PASS |
| `natpass` | natpass v0.13 | 非 TLS；Protobuf 握手（~86B+）；周期 keepalive | `natpass.handshake` / `natpass.keepalive` | ✅ PASS |
| `frp` | frp v0.70 | TLS 控制通道 + 固定 30s 心跳（29B 小记录） | `frp.heartbeat` | ✅ PASS |
| `sliver` | Sliver v1.7 | mTLS beacon 周期 ~30s（TLS 小记录） | `sliver.beacon` | ✅ PASS |
| `gost` | gost v2.12 | ws 中继：同源同目标周期性短流（模拟 beacon 中继） | `gost.tunnel_relay` | ✅ PASS |
| `chopper` | 菜刀 China Chopper | 非 TLS HTTP 短流（操作即连接）；z0/z1 参数 + base64 eval 载荷 | `chopper.eval_flow` | ✅ PASS |
| `ngrok` | Ngrok（真实 agent） | TLS + 固定 SNI connect.ngrok-agent.com，指数退避重连 | `ngrok.agent_tls` | ✅ PASS |
| `adaptix` | AdaptixC2 | 非 TLS HTTP 单端点短流；POST /checkin + RC4 载荷；8s±20% checkin | `adaptix.checkin` | ✅ PASS |
| `nimplant` | NimPlant | HTTPS beacon 短流；固定 SNI + 加密二进制载荷；15s±20% 周期 | `nimplant.beacon` | ✅ PASS |
| `bruteratel` | Brute Ratel C4 | HTTPS POST beacon 短流；固定 SNI；AES/RSA 载荷；20s±15% 周期 | `bruteratel.beacon` | ✅ PASS |
| `simayrat` | SiMayRAT | HTTPS 借道云文档 C2；固定 SNI + GET 轮询（伪装 JSON）；15s±10% | `simayrat.poll` | ✅ PASS |
| `oceanlotus` | 海莲花 OceanLotus | HTTPS 远控周期回连；固定 SNI/UA；请求>响应；20s±20% | `oceanlotus.beacon` | ✅ PASS |
| `transparenttribe` | 摩诃草 | HTTPS 借道 Telegram API 短轮询；响应>请求；10s±10% | `transparenttribe.poll` | ✅ PASS |
| `normal` | 正常 HTTPS GET | — | 零告警 | ✅ PASS（负样本） |

## React 前端（web/）

```bash
cd lab/web
npm install && npm run build     # 产物在 dist/
npm run dev                      # 开发模式
```

- 工具总表：59 个工具，59 个已集成打勾，含**加密流量指纹列**（实测/资料整理标记），按类型/集成状态过滤
- 攻击详解：59 种集成攻击都有"它是什么 / 为什么是攻击 / 攻击原理 / 流量指纹（实测）/
  检测规则"详细讲解 + 真实抓包图表
- 数据自动生成：`python3 frontend/generate.py` 把 pcap 分析结果输出到 `web/public/data/`
- 文档总表自动生成：`python3 frontend/gen_tool_index.py` 由 `frontend/tools.json` 生成
  [docs/TOOL_INDEX.md](docs/TOOL_INDEX.md)
- 数据说明：每种攻击 / 良性流量的来源与生成方式见
  [docs/DATA.md](docs/DATA.md)（数据集构成、特征管线、复现命令）

### 告警中心

前端「🚨 告警中心」页展示探针输出的全部告警：统计卡（总数/分类型）、按
类型/工具筛选、关键词搜索、3 秒自动刷新。数据来源为探针 JSON 告警行
（实验室是 `data/alerts/probe_*.jsonl`，生产是 `/var/log/tflab/alerts.jsonl`）。

```bash
# 实验室：合并所有场景告警 + 起一个独立看板服务（可选，vite 预览也可直接看）
python3 frontend/collect_alerts.py
python3 frontend/alert_server.py --port 4174   # http://localhost:4174

# 生产：指向探针落盘文件，前端每 3 秒刷新
python3 frontend/alert_server.py --source /var/log/tflab/alerts.jsonl --port 4174
```

### 冰蝎指纹（文章 id=208）

| 维度 | 文章结论 | 实测 |
|---|---|---|
| 连接复用 | 内存马一操作一连接 | 10 操作 = 10 流，每流恰好 13 条 TLS 记录 |
| 记录大小 | 大块出现次数确定 | 请求侧恒定 8225B 分块（okio 8192 + TLS 开销），每交换 2–3 次 |
| 时序 | 流间无重叠、人操作节奏 | 间隔 1.5–3.5s（含 7s 读输出停顿、0.4s 连击） |
| TLS 指纹 | 客户端栈稳定 | JA3 跨连接稳定 |

### Ligolo 指纹（文章 id=181）

| 特征 | 文章（旧版） | v0.9 实测 |
|---|---|---|
| 心跳包大小 | 固定 29B | 29B（12B yamux ping + 1B 类型 + 16B GCM 标签）✅ |
| 心跳周期 | 服务端 27s / 客户端 30s | proxy 30s（yamux 默认）/ agent 60s（源码改为 60s） |
| 心跳方向 | 先下行后上行 | S→C 先于 C→S ✅ |
| 加密套件 | TLS_AES_128_GCM_SHA256 | 实测 ServerHello cipher=0x1301 ✅ |

规则阈值按 20–70s 区间设计，兼容文章旧版与 v0.9。

## 新增一个工具的流程

```bash
mkdir scenarios/<tool>
# 1. scenario.json（端口/时长/过滤/预期告警）+ run.sh（部署+流量）+ expected.json
# 2. 分析源码+抓包 → 确定指纹 → framework/probe/rules/<tool>.go 注册规则
# 3. make scenario-<tool> 跑通 → 存 golden pcap
# 4. make test 全绿（正样本命中 + normal 负样本零误报）
```

## 生产部署（传感器）

探针设计为部署在交换机镜像口（SPAN/TAP）后的 Linux 传感器上，只做**密文侧信道
提取，不解密**；告警以 JSON 行输出到 stdout，由外部采集端消费。

```bash
# 1. 传感器就绪：镜像口接到专用监控网卡（只 up、不配 IP）
# 2. 一键安装（交叉编译 + systemd 服务）
sudo bash deploy/install_probe.sh eth1 amd64
# 3. 启动并验证
systemctl start behinder-probe
journalctl -u behinder-probe -f          # 看 JSON 告警
tcpreplay -i eth1 data/captures/cap_behinder.pcap --pps=10000   # 回放验收
```

部署形态：

- **二进制**：`framework/probe/behinder-probe-linux-{amd64,arm64}` 静态编译、
  零依赖；或 `docker build -f framework/probe/Dockerfile.probe` 走容器。
- **容器方式**：`docker run --network host --cap-add=NET_ADMIN -i eth0 ...`，
  需 CAP_NET_RAW 抓包。
- **告警消费**：stdout JSON 行可直接接 Filebeat / Fluent Bit / Syslog /
  HTTP webhook；服务文件改 `StandardOutput=append:/var/log/tflab/alerts.jsonl`
  即可落盘由采集器读取。
- **关键参数**：`-idle` 流空闲超时（默认 30s）、`-window` 聚合窗口（60s）、
  `-max-flows` 流表上限（默认 10 万）、`-ja3=false` 关闭低置信度 JA3 信号。
- **镜像口调优**：`ethtool -G <iface> rx 4096 tx 4096` 加大 ring buffer；
  监控口 `ip link set <iface> promisc on` 开混杂模式（镜像口收到的是
  任意目标 MAC 的帧）、不配 IP、不走路由，避免双向重复计数。
- **运行自检**：探针 stderr 每秒打印 `frames=N flows=N`，可对照 tcpreplay
  发送量判断丢包（压测脚本见 `framework/bench/`）。

## 已知边界

- 规则阈值绑定特定客户端版本（冰蝎=JDK11+OkHttp；Ligolo=Go TLS），换版本需
  重新标定——框架的 `normal` 负样本和 golden pcap 就是为此设计的
- IPv6 扩展头暂不支持
- 59 个工具已全部集成（11 个真实工具/协议复刻 + 48 个协议驱动仿真），其中
  闭源工具按公开分析做仿真，换版本/换变种需重新标定
- suo5 的 JA3 随机化规则与冰蝎存在交叉命中（两者都是 JA3 随机化客户端），
  全规则部署时该告警按"JA3 随机化（反检测行为）"解读
- 探针已在实验室全量 60/60 场景验证；**生产级高流量压测（PPS/CPU/内存拐点）
  尚在进行中**，结果会更新到 `docs/PERF.md`
