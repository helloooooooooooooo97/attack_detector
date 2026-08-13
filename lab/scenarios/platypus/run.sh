#!/bin/bash
# Platypus v1.5.1: enroll an agent headlessly via the bootstrap -> login ->
# install-artifact -> bundle flow, then hold the TLS link.
set +e
OUT="${OUT:-/lab/src/out}"
mkdir -p "$OUT" /lab/pp/releases

cp /lab/bin/tools/platypus/platypus-server /tmp/ps && chmod +x /tmp/ps
cp /lab/bin/tools/platypus/platypus-agent /tmp/pa && chmod +x /tmp/pa

# releases/ dir enables the distributor, which serves the install bundle
/tmp/ps --listen 127.0.0.1:13338 --external-addr 127.0.0.1:13338 --dev \
  --data-dir /lab/pp > "$OUT/platypus_server.log" 2>&1 &
SERVER=$!
for i in $(seq 1 30); do
  [ -f /lab/pp/bootstrap.secret ] && break
  sleep 1
done

SECRET=$(cat /lab/pp/bootstrap.secret)
curl -sk -X POST https://127.0.0.1:13338/api/v1/auth/bootstrap \
  -H "Content-Type: application/json" \
  -d "{\"secret\":\"$SECRET\",\"username\":\"admin\",\"password\":\"Admin@123\"}" >/dev/null
LOGIN=$(curl -sk -X POST https://127.0.0.1:13338/api/v1/auth/login \
  -H "Content-Type: application/json" -d "{\"username\":\"admin\",\"password\":\"Admin@123\"}")
TOKEN=$(echo "$LOGIN" | grep -o "\"session_token\":\"[^\"]*\"" | cut -d\" -f4)
RESP=$(curl -sk -X POST "https://127.0.0.1:13338/api/v1/projects/default/install-artifacts" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d "{\"server_endpoint\":\"127.0.0.1:13338\",\"target_os\":\"linux\",\"target_arch\":\"arm64\",\"ttl_seconds\":3600,\"pat_ttl_seconds\":3600,\"pat_max_uses\":10,\"auto_approve\":true}")
ITOKEN=$(echo "$RESP" | grep -o "\"download_token\":\"[^\"]*\"" | cut -d\" -f4)
BUNDLE=$(curl -sk "https://127.0.0.1:13338/api/v1/install/$ITOKEN?format=bundle")
echo "bundle_ok=$([ -n "$BUNDLE" ] && echo 1 || echo 0)" > "$OUT/platypus.log"

/tmp/pa "$BUNDLE" > "$OUT/platypus_agent.log" 2>&1 &
AGENT=$!
sleep 45
kill "$AGENT" "$SERVER" 2>/dev/null
echo "platypus scenario done" >> "$OUT/platypus.log"
exit 0
