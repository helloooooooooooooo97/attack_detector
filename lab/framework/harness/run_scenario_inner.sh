#!/bin/bash
# Generic in-container scenario runner.
# Starts tcpdump + the Go probe, then executes the scenario's run.sh.
set +e

: "${SCENARIO:?} ${OUT:?}"
FILTER="${FILTER:-tcp}"
DURATION="${DURATION:-120}"
PROBE_ARGS="${PROBE_ARGS:--json}"
mkdir -p "$OUT/captures" "$OUT/alerts"

tcpdump -i lo -s 0 -w "$OUT/captures/cap_$SCENARIO.pcap" $FILTER >/dev/null 2>&1 &
TCPID=$!

/lab/src/framework/probe/behinder-probe-linux-arm64 -i lo $PROBE_ARGS \
  > "$OUT/alerts/probe_$SCENARIO.jsonl" 2>"$OUT/alerts/probe_$SCENARIO.err" &
PROBE=$!

sleep 1
echo "[harness] running scenario $SCENARIO (max ${DURATION}s)" >&2
timeout "${DURATION}" bash "/lab/src/scenarios/$SCENARIO/run.sh"
RC=$?

# grace for flow eviction / scoring, then stop capture and probe
sleep 12
kill "$TCPID" "$PROBE" 2>/dev/null
sleep 1
# keep the scenario artifact root tidy: scenario logs -> data/logs/
if [ -d "$OUT" ]; then
  mkdir -p "$OUT/logs"
  mv "$OUT"/*.log "$OUT"/logs/ 2>/dev/null || true
fi
echo "[harness] scenario $SCENARIO rc=$RC" >&2
exit 0
