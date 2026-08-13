#!/bin/bash
set +e
OUT="${OUT:-/lab/src/out}"
mkdir -p "$OUT"

cp /lab/bin/tools/stowaway/admin /tmp/admin && chmod +x /tmp/admin
cp /lab/bin/tools/stowaway/agent /tmp/agent && chmod +x /tmp/agent

# admin needs a PTY for its terminal UI
TERM=xterm-256color script -qec "/tmp/admin -l 10000 -s test" /dev/null \
  > "$OUT/stowaway_admin.log" 2>&1 &
ADMIN=$!
sleep 2
/tmp/agent -c 127.0.0.1:10000 -s test > "$OUT/stowaway_agent.log" 2>&1 &
AGENT=$!
sleep 30
kill "$AGENT" "$ADMIN" 2>/dev/null
echo "stowaway scenario done" >> "$OUT/stowaway.log"
exit 0
