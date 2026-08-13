#!/bin/bash
# Ligolo-ng scenario: start proxy + agent, hold the TLS+yamux session so
# heartbeat fingerprints accumulate. Run by the harness (capture+probe are
# already running). Article id=181: 27s/30s heartbeats in the analyzed
# version; v0.9 uses proxy 30s (yamux default) / agent 60s.
set +e

OUT="${OUT:-/lab/src/out}"
mkdir -p "$OUT" /lab/ligolo-work
LIG=/lab/bin/ligolo
cd /lab/ligolo-work

command -v openssl >/dev/null 2>&1 || apt-get install -y -q openssl >/dev/null 2>&1

# --- start the proxy (daemon mode skips the interactive WebUI prompt) ---
"$LIG/proxy" -daemon -selfcert -nobanner > "$OUT/ligolo_proxy.log" 2>&1 &
PROXY_PID=$!
sleep 2

# --- force certificate generation with a dummy TLS handshake ---
curl -sk -o /dev/null https://127.0.0.1:11601/ 2>/dev/null
sleep 1

# --- compute the served certificate fingerprint (SHA256 of DER) ---
FP=$(echo | openssl s_client -connect 127.0.0.1:11601 2>/dev/null \
       | openssl x509 -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1)
echo "proxy_pid=$PROXY_PID fingerprint=${FP:-none}" > "$OUT/ligolo.log"

# --- start the agent with fingerprint verification ---
if [ -n "$FP" ]; then
  "$LIG/agent" -connect 127.0.0.1:11601 -accept-fingerprint "$FP" \
    > "$OUT/ligolo_agent.log" 2>&1 &
  AGENT_PID=$!
else
  "$LIG/agent" -connect 127.0.0.1:11601 -ignore-cert \
    > "$OUT/ligolo_agent.log" 2>&1 &
  AGENT_PID=$!
  echo "using -ignore-cert (no fingerprint)" >> "$OUT/ligolo.log"
fi
echo "agent_pid=$AGENT_PID" >> "$OUT/ligolo.log"
sleep 5

# hold the session: enough for 4+ proxy heartbeats (30s) and 2 agent (60s)
sleep "${LIGOLO_SECONDS:-140}"

kill "$AGENT_PID" "$PROXY_PID" 2>/dev/null
echo "ligolo scenario done" >> "$OUT/ligolo.log"
exit 0
