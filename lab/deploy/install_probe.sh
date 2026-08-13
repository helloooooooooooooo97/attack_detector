#!/bin/bash
# TFLab 探针生产部署脚本（Linux 传感器）
#
# 用法:
#   sudo bash deploy/install_probe.sh [监控网卡名] [架构]
#   示例: sudo bash deploy/install_probe.sh eth1 amd64
#
# 前置: 交换机镜像口(SPAN/TAP)已接到监控网卡；监控网卡不要配置 IP。
set -euo pipefail

IFACE="${1:-eth1}"
ARCH="${2:-$(uname -m | sed -e 's/x86_64/amd64/' -e 's/aarch64/arm64/')}"
LAB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BIN=/usr/local/bin/behinder-probe
UNIT=/etc/systemd/system/behinder-probe.service

echo "[1/4] 交叉编译 linux-$ARCH 静态探针"
cd "$LAB_DIR/framework/probe"
make "linux-$ARCH" >/dev/null
install -m 0755 "behinder-probe-linux-$ARCH" "$BIN"

echo "[2/4] 写入 systemd 服务 (iface=$IFACE)"
sed "s/@PROBE_IFACE@/$IFACE/" "$LAB_DIR/deploy/behinder-probe.service" > "$UNIT"

echo "[3/4] 启用服务"
systemctl daemon-reload
systemctl enable behinder-probe >/dev/null

echo "[4/4] 校验监控网卡"
if ! ip link show "$IFACE" >/dev/null 2>&1; then
  echo "警告: 网卡 $IFACE 不存在，请检查镜像口接线后运行: systemctl start behinder-probe" >&2
else
  # 监控口：up + promiscuous，不配 IP（避免流量进入协议栈）
  ip link set "$IFACE" up 2>/dev/null || true
  ip link set "$IFACE" promisc on 2>/dev/null || true
  echo "网卡 $IFACE 已 up（未配置 IP，仅收包）"
fi

echo
echo "完成。启动:  systemctl start behinder-probe"
echo "看告警:    journalctl -u behinder-probe -f"
echo "压测验收:  tcpreplay -i $IFACE <lab>/data/captures/cap_behinder.pcap --pps=10000"
echo "确认镜像口 ring buffer 建议:  ethtool -G $IFACE rx 4096 tx 4096"
