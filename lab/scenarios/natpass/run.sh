#!/bin/bash
set +e
OUT="${OUT:-/lab/src/out}"
mkdir -p "$OUT" /lab/natpass
NP=/lab/bin/tools/natpass/natpass_0.13.0
cp -r "$NP" /lab/natpass/
cd /lab/natpass/natpass_0.13.0
chmod +x np-svr np-cli
mkdir -p logs

./np-svr -c server.yaml > "$OUT/natpass_svr.log" 2>&1 &
SVR=$!
sleep 2
./np-cli -c remote.yaml > "$OUT/natpass_cli.log" 2>&1 &
CLI=$!
sleep 30
kill "$CLI" "$SVR" 2>/dev/null
echo "natpass scenario done" >> "$OUT/natpass.log"
exit 0
