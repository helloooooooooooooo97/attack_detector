#!/bin/bash
# Probe load test: pump a synthetic pcap through a veth "mirror port" at a
# target PPS and measure capture ratio, CPU, RSS and alert count.
#
# Runs INSIDE the tflab-bench container (NET_ADMIN + network none):
#   tcpreplay -i vA --pps=P  →  veth pair  →  probe on vB
#
# Usage: bash framework/bench/run_bench.sh <pps> <duration> <pcap>
set -u
PPS="${1:?pps}"
DUR="${2:?duration}"
PCAP="${3:?pcap}"
OUT=/lab/src/out
PROBE=/lab/src/framework/probe/behinder-probe-linux-arm64

# TAP device: tcpreplay injects Ethernet frames via the tap fd (veth +
# TX_RING hits TP_STATUS_WRONG_FORMAT in containers).
ip tuntap add dev tapA mode tap
ip link set tapA up

"$PROBE" -i tapA -json -ja3=false -idle 15 -window 60 \
  > "$OUT/bench_alerts_$PPS.jsonl" 2> "$OUT/bench_probe_$PPS.log" &
PROBE_PID=$!
sleep 1

# sample CPU (delta ticks) + RSS every second
(
  prev=$(awk '{print $14+$15}' "/proc/$PROBE_PID/stat" 2>/dev/null || echo 0)
  pt=$SECONDS
  while kill -0 "$PROBE_PID" 2>/dev/null; do
    sleep 1
    cur=$(awk '{print $14+$15}' "/proc/$PROBE_PID/stat" 2>/dev/null || echo 0)
    dt=$((SECONDS - pt)); pt=$SECONDS
    ticks=$((cur - prev)); prev=$cur
    clk=$(getconf CLK_TCK 2>/dev/null || echo 100)
    cpu=$(awk -v t="$ticks" -v d="$dt" -v c="$clk" 'BEGIN{printf "%.1f", (d>0 ? 100*t/(d*c) : 0)}')
    rss=$(awk '/VmRSS/{print $2}' "/proc/$PROBE_PID/status" 2>/dev/null || echo 0)
    echo "$SECONDS cpu=$cpu rss_kb=$rss"
  done
) > "$OUT/bench_cpu_$PPS.log" &
SAMPLER=$!

if [ "$PPS" = "topspeed" ]; then
  tcpreplay -i tapA --topspeed "$PCAP" \
    > "$OUT/bench_tcpreplay_topspeed.log" 2>&1
elif [ "${LOOP:-0}" = "1" ]; then
  tcpreplay -i tapA --pps="$PPS" --loop=0 --duration="$DUR" "$PCAP" \
    > "$OUT/bench_tcpreplay_$PPS.log" 2>&1
else
  tcpreplay -i tapA --pps="$PPS" "$PCAP" \
    > "$OUT/bench_tcpreplay_$PPS.log" 2>&1
fi
TC_RC=$?

# let flow eviction settle, then ask the probe to flush via SIGTERM
sleep 8
kill -TERM "$PROBE_PID" 2>/dev/null
wait "$PROBE_PID" 2>/dev/null
kill "$SAMPLER" 2>/dev/null
ip link del tapA 2>/dev/null

sent=$(grep -oE "Actual: [0-9]+ packets" "$OUT/bench_tcpreplay_$PPS.log" | head -1 | grep -oE "[0-9]+")
frames=$(grep -oE "frames=[0-9]+" "$OUT/bench_probe_$PPS.log" | tail -1 | grep -oE "[0-9]+")
alerts=$(wc -l < "$OUT/bench_alerts_$PPS.jsonl")
loss=""
if [ -n "$sent" ] && [ -n "$frames" ] && [ "$sent" -gt 0 ] 2>/dev/null; then
  loss=$(awk -v s="$sent" -v f="$frames" 'BEGIN{printf "%.2f", (s>f ? (s-f)*100.0/s : 0)}')
fi
echo "RESULT pps=$PPS sent=$sent frames=$frames loss_pct=$loss alerts=$alerts tc_rc=$TC_RC"
