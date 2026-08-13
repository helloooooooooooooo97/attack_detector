#!/bin/bash
# DeimosC2 scenario: real Deimos TCP agent (built from DeimosC2 source with
# the server's template substitution) talking to a minimal listener that
# speaks the exact Deimos wire protocol (RSA-OAEP + AES-256-CBC + 8B length).
# Agent check-in interval is 15s; run long enough for 3+ check-ins.
set +e
OUT="${OUT:-/lab/src/out}"
mkdir -p "$OUT" /lab/deimos
cp /lab/bin/tools/deimos/deimos-driver /lab/bin/tools/deimos/deimos-agent /lab/deimos/
chmod +x /lab/deimos/deimos-*
cp /lab/src/framework/drivers/deimos/keys/priv.pem /lab/deimos/
cd /lab/deimos

./deimos-driver -key priv.pem -port 14000 -seconds 90 > "$OUT/deimos_drv.log" 2>&1 &
DRV=$!
sleep 2
./deimos-agent > "$OUT/deimos_agent.log" 2>&1 &
AGT=$!

# hold for 4+ check-ins (15s interval)
sleep 75
kill "$AGT" "$DRV" 2>/dev/null
echo "deimos scenario done" >> "$OUT/deimos.log"
exit 0
