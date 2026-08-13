#!/bin/bash
# Mythic scenario: run the real Athena (C) linux-arm64 agent built by the
# Mythic payload system against the host Mythic stack (http profile on :80).
# Requires the stack from framework/mythic_stack/start.sh to be running.
set +e
OUT="${OUT:-/lab/src/out}"
mkdir -p "$OUT" /lab/mythic
cp /lab/bin/tools/mythic/athena_agent /lab/bin/tools/mythic/libMono.Unix.so /lab/mythic/
chmod +x /lab/mythic/athena_agent
cd /lab/mythic

./athena_agent > "$OUT/mythic_agent.log" 2>&1 &
AGT=$!
sleep 60
kill "$AGT" 2>/dev/null
echo "mythic scenario done" >> "$OUT/mythic.log"
exit 0
