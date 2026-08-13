#!/bin/bash
# Shared runner for protocol-driven beacon/RAT scenarios.
#
# Reads framework/drivers/beacon/profiles/<tool>.json, starts the local lab
# C2 endpoint (HTTP / HTTPS / raw TCP) and runs the beacon agent against it
# inside the lab container. Used by scenarios/<tool>/run.sh.
set +e
TOOL="${1:?usage: run_beacon_scenario.sh <tool>}"
OUT="${OUT:-/lab/src/data}"
PROF="/lab/src/framework/drivers/beacon/profiles/$TOOL.json"
ASSETS="/lab/src/scenarios/$TOOL/assets"
mkdir -p "$OUT/logs"

DURATION=$(python3 -c "import json;print(json.load(open('$PROF')).get('duration',60))")

python3 - "$PROF" > "$OUT/logs/.${TOOL}_endpoints" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
eps = []
def add(transport, port, host):
    if transport not in ("http", "https", "tcp", "udp"):
        return
    if not any(e[0] == transport and e[1] == port for e in eps):
        eps.append((transport, port))
    if host and host != "127.0.0.1":
        print(host)
add(d.get("transport"), d.get("port"), d.get("host"))
for ph in d.get("phases", []):
    add(ph.get("transport", d.get("transport")), ph.get("port", d.get("port")), ph.get("host", d.get("host")))
for ep in eps:
    print(f"{ep[0]} {ep[1]}")
PY

while read -r transport port; do
  case "$transport" in
    http|https|tcp|udp)
      extra=""
      if [ "$transport" = "https" ]; then
        extra="--cert $ASSETS/${TOOL}_cert.pem --key $ASSETS/${TOOL}_key.pem"
      fi
      python3 /lab/src/framework/drivers/beacon/beacon_server.py \
        --transport "$transport" --port "$port" $extra \
        > "$OUT/${TOOL}_${port}_srv.log" 2>&1 &
      SRVS="$SRVS $!"
      ;;
    *)
      grep -q "$transport" /etc/hosts || echo "127.0.0.1 $transport" >> /etc/hosts
      ;;
  esac
done < <(tail -n +1 "$OUT/logs/.${TOOL}_endpoints")
sleep 1

SEED_ARGS=""
if [ -n "${BEACON_SEED:-}" ]; then
  SEED_ARGS="--seed $BEACON_SEED"
fi
timeout "$((DURATION + 10))" python3 /lab/src/framework/drivers/beacon/beacon_agent.py \
  --profile "$PROF" $SEED_ARGS > "$OUT/${TOOL}_drv.log" 2>&1
RC=$?
kill $SRVS 2>/dev/null
echo "$TOOL scenario rc=$RC" >> "$OUT/$TOOL.log"
exit 0
