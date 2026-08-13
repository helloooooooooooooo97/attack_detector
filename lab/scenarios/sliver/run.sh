#!/bin/bash
set +e
OUT="${OUT:-/lab/src/out}"
mkdir -p "$OUT" /lab/sliver

cp /lab/bin/tools/sliver-server /tmp/sliver && chmod +x /tmp/sliver
cd /lab/sliver
/tmp/sliver unpack > "$OUT/sliver_unpack.log" 2>&1

cat > /lab/sliver/rc.txt <<'EOF'
mtls --lhost 127.0.0.1
generate --mtls 127.0.0.1 --os linux --arch arm64 --skip-symbols --save /lab/sliver/implant
EOF

# keep stdin open so the console stays alive after the rc script runs
tail -f /dev/null | /tmp/sliver --rc /lab/sliver/rc.txt > "$OUT/sliver_server.log" 2>&1 &
SERVER=$!
for i in $(seq 1 180); do
  [ -f /lab/sliver/implant ] && break
  sleep 2
done
if [ -f /lab/sliver/implant ]; then
  chmod +x /lab/sliver/implant
  /lab/sliver/implant > "$OUT/sliver_implant.log" 2>&1 &
  IMPLANT=$!
  sleep 70
  kill "$IMPLANT" 2>/dev/null
else
  echo "implant generation failed" > "$OUT/sliver.log"
fi
kill "$SERVER" 2>/dev/null
echo "sliver scenario done" >> "$OUT/sliver.log"
exit 0
