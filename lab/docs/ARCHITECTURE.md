# 加密流量指纹实验室 —— 通用框架架构

目标：把"分析某个工具/恶意家族的加密流量指纹并做检测"沉淀为可复用的流水线。
每增加一个工具，只需要新增一个**场景模块**（场景目录 + 一个规则文件），
抓包、解析、检测、验证全部复用通用框架。

## 设计原则

1. **一条流水线，N 个场景**：采集（容器内 tcpdump）→ 解析（共享 TLS 流特征
   引擎）→ 检测（规则注册表，每个工具注册自己的规则）→ 验证（金标准 + 负样本）。
2. **场景即模块**：每个工具一个目录，自包含三样东西——如何部署并产生流量
   （`run.sh`）、预期指纹/告警（`expected.json`）、检测规则（Go 规则 + YARA/
   Suricata）。目录结构就是工具目录。
3. **通用核心与工具无关**：`framework/` 里没有任何具体工具名字；工具逻辑只
   存在于 `scenarios/<tool>/` 和规则包 `rules/<tool>.go`。
4. **负样本内置**：`normal/` 场景是正常流量基线，每次测试都跑，防止规则把
   正常流量误报成恶意。
5. **可回归**：离线金标准 pcap + 在线场景运行双通道验证；改规则后一键重跑
   全部场景。
6. **协议驱动仿真**：Windows-only / 闭源工具无法跑真实 agent，统一用
   `framework/drivers/beacon/`（每工具一份 profile：传输/URI/参数/载荷尺寸/
   周期/SNI/UA）在本地 C2 端点产生忠实流量；探针规则用「行为特征 + 专属
   SNI/raw marker」区分，避免不同 beacon 互相误报。
   支持 6 种流量模式：`http`（短流 beacon）、`tcp_stream`（长连接 + 固定
   帧头心跳）、`udp`（周期小包暗道）、`burst`（窃密型上行突发）、
   `multiphase`（投递 + 驻留多阶段）、keep-alive 长连接（gRPC 形态）。

## 文件结构

```
lab/
├── Makefile                          # build / run-scenario / test / report
├── docs/
│   └── ARCHITECTURE.md               # 本文档
├── framework/                        # 通用框架（与具体工具无关）
│   ├── analyze.py                    # pcap → TLS 流特征引擎（共享）
│   ├── rules.py                      # Python 规则注册表（离线/回放检测）
│   ├── probe/                        # Go 实时探针（通用核心）
│   │   ├── main.go                   # CLI / 抓包 / 回放
│   │   ├── tracker.go                # TCP 流重建 + TLS 记录解析 + JA3
│   │   ├── registry.go               # 规则注册表：规则 = 插件
│   │   ├── capture_linux.go          # AF_PACKET 实时抓包（Linux）
│   │   └── rules/                    # 场景规则包（按工具拆分）
│   │       ├── behinder.go           # 冰蝎规则
│   │       └── ligolo.go             # Ligolo-ng 规则
│   └── harness/
│       ├── Dockerfile                # 基础实验镜像（JDK/Tomcat 等公共依赖）
│       └── run_scenario.sh           # 通用场景运行器（容器内执行）
├── scenarios/                        # 工具场景模块（每个工具一个目录）
│   ├── behinder/
│   │   ├── scenario.yaml             # 元数据：端口、时长、抓包过滤、预期
│   │   ├── run.sh                    # 部署 webshell + 驱动冰蝎客户端流量
│   │   ├── expected.json             # 预期告警（金标准）
│   │   └── rules/
│   │       └── behinder.yara         # 主机侧 webshell 文件规则
│   ├── ligolo/
│   │   ├── scenario.yaml
│   │   ├── run.sh                    # 起 proxy/agent + 建立隧道会话
│   │   └── expected.json
│   └── normal/                       # 正常流量基线（负样本）
│       ├── scenario.yaml
│       ├── run.sh                    # 正常浏览 GET
│       └── expected.json             # 预期：零告警
├── test/
│   ├── test_runner.py                # 跑场景 + 校验告警 + 生成报告
│   └── golden/                       # 金标准 pcap（离线回归）
└── out/                              # 运行产物（gitignored）
```

## 场景模块契约

每个 `scenarios/<tool>/` 必须提供：

| 文件 | 作用 | 契约 |
|---|---|---|
| `scenario.yaml` | 元数据 | 场景名、容器镜像、端口、时长、抓包过滤器、探针参数、预期告警 |
| `run.sh` | 部署+流量 | 在容器内执行；负责把工具跑起来并产生目标流量；结束前清理 |
| `expected.json` | 金标准 | 期望的告警事件列表 `{event, min_count}`；`negative: true` 表示应零告警 |

## 流水线（一次场景运行）

```
harness/run_scenario.sh <scenario>
  1. 启动容器（挂载 scenarios/、out/、工具二进制目录）
  2. 并行启动：tcpdump 抓包 + Go 探针（-scenario=<tool> 加载对应规则）
  3. 执行 scenarios/<tool>/run.sh（部署工具 + 驱动流量）
  4. 等待场景结束 → 停抓包/停探针
  5. 产物：cap_<tool>.pcap、probe_<tool>.jsonl、<tool>.log → out/
test/test_runner.py out/... expected.json
  6. 校验探针告警命中预期（正样本 ≥ min_count，负样本 = 0）
  7. 输出 PASS/FAIL 报告
```

## 测试设计

**测试矩阵**（每新增一个工具，自动加入矩阵）：

| 场景 | 类型 | 预期 |
|---|---|---|
| `behinder` | 正样本 | `behinder.mem_shell_flow` ≥3、`behinder.memory_shell_aggregate` ≥1 |
| `ligolo` | 正样本 | `ligolo.tunnel_heartbeat` ≥1 |
| `normal` | 负样本 | 零告警 |

**三层验证**：

1. **离线回放**（最快）：`probe -r golden/<tool>.pcap`，规则改动后秒级回归。
2. **在线场景**（最真实）：容器内起真实工具 + 探针实时抓，验证端到端。
3. **负样本回归**：`normal` 场景每次必跑，任何规则不得误报正常流量。

**新增工具的流程**：

```
1. mkdir scenarios/<tool>  写 scenario.yaml / run.sh / expected.json
2. 分析源码 + 抓包 → 确定指纹 → framework/probe/rules/<tool>.go 注册规则
3. 跑一次场景 → golden 存 pcap
4. make test 全绿
```

**协议驱动工具（真实 agent 不可运行）**：

```
1. framework/drivers/beacon/profiles/<tool>.json  定义流量形态
2. framework/probe/rules/<tool>.go                行为 + SNI/raw marker 规则
3. scenarios/<tool>/{scenario.json,run.sh,expected.json}
   run.sh 一行：exec run_beacon_scenario.sh <tool>
4. make scenario-<tool> && make test 全绿
```

## 为什么按工具拆文件而不是按"检测层"拆

按工具拆分（`scenarios/<tool>/` + `rules/<tool>.go`）是因为**指纹知识天然按
工具聚集**：冰蝎的特征是 8225B 分块 + 单流单操作；Ligolo 的特征是心跳周期 +
29B 固定包长。按层拆（TLS 记录层/流层/时序层）会让同一个工具的规则散落多处。
通用核心（解析、抓包、规则引擎）放在 `framework/`，工具知识放在 `scenarios/`，
各自职责单一。
