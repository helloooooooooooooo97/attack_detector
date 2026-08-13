#!/bin/bash
# XiebroC2 scenario: real Linux TCP client pinging a minimal listener that
# speaks the wire format (4B LE length + AES-128-ECB with fixed key).
# Client pings every 15s; hold the session for 4+ pings.
set +e
OUT="${OUT:-/lab/src/out}"
mkdir -p "$OUT" /lab/xiebro
cp /lab/bin/tools/xiebro/xiebro-driver /lab/bin/tools/xiebro/xiebro-client /lab/xiebro/
chmod +x /lab/xiebro/xiebro-*
cd /lab/xiebro

./xiebro-driver -port 13000 -seconds 90 > "$OUT/xiebro_drv.log" 2>&1 &
DRV=$!
sleep 2
./xiebro-client > "$OUT/xiebro_client.log" 2>&1 &
CLI=$!

sleep 75
kill "$CLI" "$DRV" 2>/dev/null
echo "xiebro scenario done" >> "$OUT/xiebro.log"
exit 0
