#!/bin/bash
# sish scenario: real sish server + OpenSSH -R reverse tunnel.
# A local PHP page is exposed through the tunnel; the SSH control channel
# stays up with 5s keepalives on both sides.
set +e
OUT="${OUT:-/lab/src/out}"
mkdir -p "$OUT" /tmp/sish /var/www/loc
cp -r /lab/bin/tools/sish/sish-2.23.0.linux-arm64/. /tmp/sish/
cd /tmp/sish && chmod +x sish

command -v ssh >/dev/null 2>&1 || apt-get update -qq >/dev/null 2>&1 && \
  apt-get install -y -qq openssh-client >/dev/null 2>&1

echo "hello from local" > /var/www/loc/index.html
php -d session.save_path=/tmp -S 127.0.0.1:9090 -t /var/www/loc > "$OUT/sish_local.log" 2>&1 &
LOCAL=$!
sleep 1

./sish --authentication=false --http-address=localhost:8081 \
  --bind-random-ports=false --force-requested-ports > "$OUT/sish_svr.log" 2>&1 &
SVR=$!
sleep 3

ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o ServerAliveInterval=5 -N -R 8080:localhost:9090 tcp@127.0.0.1 -p 2222 \
  > "$OUT/sish_ssh.log" 2>&1 &
SSH=$!
sleep 5

curl -s http://127.0.0.1:8080/ > "$OUT/sish_tunnel.log" 2>&1
sleep 45

kill "$SSH" "$SVR" "$LOCAL" 2>/dev/null
echo "sish scenario done" >> "$OUT/sish.log"
exit 0
