#!/bin/bash
# shadow-tls scenario: real v0.2.25 client+server wrapping plaintext HTTP
# inside a TLS handshake to github.com (camouflage target). Requires outbound
# internet from the lab container; retries make it resilient.
set +e
OUT="${OUT:-/lab/src/out}"
mkdir -p "$OUT" /tmp/st /var/www/loc
cp /lab/bin/tools/shadowtls/shadow-tls /tmp/st/ && chmod +x /tmp/st/shadow-tls
cd /tmp/st

echo "shadow tls data OK" > /var/www/loc/index.html
php -S 127.0.0.1:8080 -t /var/www/loc > "$OUT/st_data.log" 2>&1 &
DATA=$!
sleep 1

./shadow-tls --v3 server --listen 127.0.0.1:8444 --server 127.0.0.1:8080 \
  --tls github.com:443 --password labpass > "$OUT/st_svr.log" 2>&1 &
SVR=$!
sleep 1
./shadow-tls --v3 client --listen 127.0.0.1:7443 --server 127.0.0.1:8444 \
  --sni github.com --password labpass > "$OUT/st_cli.log" 2>&1 &
CLI=$!
sleep 2

for i in $(seq 1 8); do
  curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:7443/ >> "$OUT/st_tunnel.log" 2>&1
  sleep 3
done

kill "$CLI" "$SVR" "$DATA" 2>/dev/null
echo "shadowtls scenario done" >> "$OUT/shadowtls.log"
exit 0
