#!/bin/bash
# Cobalt Strike beacon protocol scenario: the geacon beacon (a Go re-
# implementation of the CS 4.x beacon wire protocol, byte-compatible with
# the default HTTP profile) talks to a minimal teamserver emulator that
# speaks the same protocol (RSA metadata decrypt + AES/HMAC tasking).
set +e
OUT="${OUT:-/lab/src/out}"
mkdir -p "$OUT" /lab/cs
cp /lab/bin/tools/cobaltstrike/geacon-beacon \
   /lab/bin/tools/cobaltstrike/cs-teamserver \
   /lab/bin/tools/cobaltstrike/priv.pem /lab/cs/
chmod +x /lab/cs/geacon-beacon /lab/cs/cs-teamserver
cd /lab/cs

./cs-teamserver -addr 127.0.0.1:8080 -key priv.pem > "$OUT/cs_ts.log" 2>&1 &
TS=$!
sleep 1
./geacon-beacon > "$OUT/geacon.log" 2>&1 &
BEACON=$!

sleep 45
kill "$BEACON" "$TS" 2>/dev/null
echo "cobaltstrike scenario done" >> "$OUT/cobaltstrike.log"
exit 0
