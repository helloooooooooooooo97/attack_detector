#!/bin/bash
# Generic scenario runner (host side).
#
# usage: run_scenario.sh <scenario> [behinder_bin_dir]
#
# Reads scenarios/<scenario>/scenario.json, starts the lab container with the
# right mounts, and runs run_scenario_inner.sh inside it. Artifacts land in
# lab/data/ (captures/cap_<scenario>.pcap, alerts/probe_<scenario>.jsonl,
# logs/<scenario>.log ...).
set -euo pipefail

SCENARIO="${1:?usage: run_scenario.sh <scenario>}"
LAB_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
BIN_DIR="${2:-/tmp/behinder_lab}"
OUT_DIR="$LAB_DIR/data"

if [ ! -f "$LAB_DIR/scenarios/$SCENARIO/scenario.json" ]; then
  echo "error: unknown scenario $SCENARIO" >&2
  exit 1
fi

mkdir -p "$OUT_DIR/captures" "$OUT_DIR/alerts" "$OUT_DIR/logs"

# parse metadata with the host python3 (no yaml dependency); source the result
ENV_FILE="$OUT_DIR/logs/.scenario_$SCENARIO.env"
python3 - "$LAB_DIR/scenarios/$SCENARIO/scenario.json" > "$ENV_FILE" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
fields = {
    "IMAGE": d.get("image", "behinder-lab"),
    "FILTER": d.get("capture_filter", "tcp"),
    "DURATION": str(d.get("duration", 120)),
    "PROBE_ARGS": d.get("probe_args", "-json"),
    "NETWORK": d.get("network", "bridge"),
}
for k, v in fields.items():
    print(f"{k}={json.dumps(v)}")
PY
# shellcheck disable=SC1090
. "$ENV_FILE"

echo "[harness] scenario=$SCENARIO image=$IMAGE filter='$FILTER' duration=$DURATION"

docker run --rm \
  --network "$NETWORK" \
  -e SCENARIO="$SCENARIO" \
  -e FILTER="$FILTER" \
  -e DURATION="$DURATION" \
  -e PROBE_ARGS="$PROBE_ARGS" \
  -e BEACON_SEED="${BEACON_SEED:-}" \
  -e OUT=/lab/src/data \
  -v "$BIN_DIR":/lab/bin:ro \
  -v "$LAB_DIR":/lab/src:rw \
  "$IMAGE" bash /lab/src/framework/harness/run_scenario_inner.sh
