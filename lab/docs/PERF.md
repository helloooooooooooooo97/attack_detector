# 探针性能与极限压测

## 结论（ARM64 Linux，Docker 内，单核捕获线程）

| 灌入速率 | 丢包率(默认缓冲) | 丢包率(SO_RCVBUF=64MB) | 探针 CPU | 探针 RSS |
|---|---|---|---|---|
| 100k pps / 0.95 Gbps | 2.7% | **0.00%** | ~24% | 88MB |
| 200k pps / 1.9 Gbps | 3.6% | **0.00%** | ~24% | 101MB |
| ~320k pps / 3.0 Gbps | 59.5% | **0.00%** | ~28% | 129MB |
| topspeed 602k pps / 5.7 Gbps | — | **0.00%** | ~21% | 121MB |

**实测极限：602,695 pps（5.7 Gbps）灌入 100% 捕获、零丢包**，探针 CPU 仅约
1/5 核——注入泵（本机 tcpreplay）已到上限，探针本身还有余量（按线性外推
单核约可到 2-3M pps，需更快的发包器验证）。

## 关键调优：AF_PACKET 接收缓冲

默认 socket 缓冲在 ~300k pps 突发时直接把丢包率打到 60%（瓶颈是内核 socket
缓冲，不是 CPU——此时 CPU 只有 ~20%）。在
`framework/probe/capture_linux.go` 给 AF_PACKET socket 设置
`SO_RCVBUFFORCE`/`SO_RCVBUF = 64MB` 后，同一负载降为 **0 丢包**。

## 检测正确性（高负载下）

合成流量含冰蝎形态 TLS 流（8225B 分块、13 记录、单交换），各档速率下
`behinder.mem_shell_flow` 告警数一致（~11.7k/轮），说明检测逻辑在高吞吐下
不丢规则、不漏判。

## 复现

```bash
# 1. 压测镜像（含 iproute2 + tcpreplay）
docker build -t tflab-bench -f framework/bench/Dockerfile.bench framework/harness
# 2. 生成 50 万包合成混合流量（550MB）
python3 framework/bench/gen_pcap.py 500000
# 3. 逐档压测（TAP 设备注入；单趟模式）
docker run --rm --privileged --network none \
  -v "$PWD":/lab/src:rw tflab-bench \
  bash /lab/src/framework/bench/run_bench.sh 200000 20 /lab/src/data/captures/bench.pcap
# 4. 榨干注入器极限
docker run --rm --privileged --network none \
  -v "$PWD":/lab/src:rw tflab-bench \
  bash /lab/src/framework/bench/run_bench.sh topspeed 20 /lab/src/data/captures/bench.pcap
```

输出在 `data/bench_*.log`：`RESULT` 行给 sent/frames/丢包率/告警数，
`bench_cpu_*.log` 每秒采样 CPU+RSS。

## 边界

- 注入泵限制：本机 tcpreplay topspeed 约 600k pps（5.7 Gbps），更高的真实
  上限需要更快发包器（如 PF_RING/AF_XDP 或专用流量仪）。
- 负载模型是合成混合流量（冰蝎大包 + beacon + 短 HTTP + UDP），不代表任意
  包长分布；小包为主的流量 pps 上限会更高，全 1518B 大包场景 pps 更低。
- 流表默认 10 万条；压测中 RSS 峰值 121-129MB（含 50 万流重放）。
