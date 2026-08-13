#!/bin/bash
set +e
OUT="${OUT:-/lab/src/out}"
mkdir -p "$OUT"

cp /lab/bin/tools/merlin/merlinServer /tmp/ms && chmod +x /tmp/ms
cp /lab/bin/tools/merlin-agent/merlinAgent /tmp/ma && chmod +x /tmp/ma

/tmp/ms -addr 127.0.0.1:50051 > "$OUT/merlin_server.log" 2>&1 &
SERVER=$!
for i in $(seq 1 40); do
  (exec 3<>/dev/tcp/127.0.0.1/50051) 2>/dev/null && break
  sleep 0.5
done
sleep 2
/tmp/ma -url https://127.0.0.1:50051 -proto h2 -psk merlin \
  > "$OUT/merlin_agent.log" 2>&1 &
AGENT=$!
sleep 60
kill "$AGENT" "$SERVER" 2>/dev/null
echo "merlin scenario done" >> "$OUT/merlin.log"
exit 0
