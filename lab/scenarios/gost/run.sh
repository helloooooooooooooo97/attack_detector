#!/bin/bash
# gost websocket relay tunnel carrying periodic (beacon-like) traffic.
# Models the real abuse pattern: an attacker relays small C2 checkins
# through a gost ws tunnel every few seconds.
set +e
OUT="${OUT:-/lab/src/out}"
mkdir -p "$OUT"
TC=/opt/tomcat

# downstream service on port 80 (Tomcat HTTP connector)
sed -i 's#port="8080"#port="80"#' "$TC/conf/server.xml"
CATALINA_HOME="$TC" "$TC/bin/catalina.sh" start >/dev/null 2>&1
for i in $(seq 1 60); do
  curl -s -o /dev/null http://127.0.0.1:80/ && break
  sleep 1
done

cp /lab/bin/tools/gost/gost /tmp/gost && chmod +x /tmp/gost

/tmp/gost -L "ws://:10080" > "$OUT/gost_svr.log" 2>&1 &
SVR=$!
sleep 1
/tmp/gost -L "tcp://:8080" -F "ws://127.0.0.1:10080" > "$OUT/gost_cli.log" 2>&1 &
CLI=$!
sleep 2

# pump small HEAD requests through the tunnel every 8s (beacon-like)
for i in $(seq 1 7); do
  curl -s -I -m 3 http://127.0.0.1:8080/ >/dev/null 2>&1
  sleep 8
done

kill "$CLI" "$SVR" 2>/dev/null
echo "gost scenario done" >> "$OUT/gost.log"
exit 0
