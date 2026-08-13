#!/bin/bash
# Parameterized reruns for rare tools (n<=5): ROUNDS rounds each.
# Beacon-driven tools get a per-round random seed (payload size + interval
# jitter); real-binary scenarios keep their native randomness. New captures
# land in data/captures/rounds/<tool>/cap_r{1..N}.pcap; the ORIGINAL capture
# is preserved as cap_r0.pcap before round 1 overwrites
# data/captures/cap_<tool>.pcap.
#
# Usage: bash scripts/rerun_rare_tools.sh [ROUNDS]
set -u

LAB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="$LAB_DIR/data/captures"
LOG_DIR="$LAB_DIR/data/logs"
RUNNER="$LAB_DIR/framework/harness/run_scenario.sh"
ROUNDS="${1:-3}"

# 39 rare tools (n<=5 in the 2026-08-13 dataset) minus the 3 without a
# scenario (keepalive / st4 / sish2 have no runnable scenario).
RARE_TOOLS="antsword apt29 aptc60 aptc68 badnews bruteratel covenant evilox \
fatalrat frp ghostwriter godzilla hemao ksrat ktlvdoor lazarus ligolo loki \
merlin mythic natpass nimplant oceanlotus oilrig rakshasa remcos \
silenttrinity simayrat sish sliver stowaway vagent vshell xiebro yinhu zloader"

mkdir -p "$OUT_DIR/rounds"
echo "batch start $(date '+%F %T') rounds=$ROUNDS"
for tool in $RARE_TOOLS; do
  if [ ! -f "$LAB_DIR/scenarios/$tool/scenario.json" ]; then
    echo "skip $tool (no scenario.json)"
    continue
  fi
  mkdir -p "$OUT_DIR/rounds/$tool"
  if [ ! -f "$OUT_DIR/rounds/$tool/cap_r0.pcap" ] && [ -s "$OUT_DIR/cap_$tool.pcap" ]; then
    cp "$OUT_DIR/cap_$tool.pcap" "$OUT_DIR/rounds/$tool/cap_r0.pcap"
    echo "backup $tool r0"
  fi
  for r in $(seq 1 "$ROUNDS"); do
    BEACON_SEED=$(( (RANDOM % 1000000) + r )) \
      bash "$RUNNER" "$tool" > "$LOG_DIR/rerun_$tool.log" 2>&1
    rc=$?
    if [ -s "$OUT_DIR/cap_$tool.pcap" ]; then
      mv "$OUT_DIR/cap_$tool.pcap" "$OUT_DIR/rounds/$tool/cap_r$r.pcap"
      n=$("$LAB_DIR/ml/.venv/bin/python" -c "import sys;sys.path.insert(0,'$LAB_DIR/ml');import build_dataset as B;print(len(B.extract_flows('$OUT_DIR/rounds/$tool/cap_r$r.pcap')))")
      echo "ok   $tool r$r rc=$rc flows=$n"
    else
      echo "fail $tool r$r rc=$rc (empty capture)"
    fi
  done
done
echo "batch done $(date '+%F %T')"
