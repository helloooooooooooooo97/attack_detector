#!/bin/bash
# Ngrok scenario: real ngrok agent binary (arm64) against a loopback TLS
# rendezvous. connect.ngrok-agent.com is redirected to 127.0.0.1; the agent
# dials it and the ClientHello (fixed SNI, TLS1.3 ciphers) is captured.
# Without an authtoken the session auth fails after the handshake, which is
# expected -- the client-side TLS fingerprint is the detection target.
set +e
OUT="${OUT:-/lab/src/out}"
ASSETS=/lab/src/scenarios/ngrok/assets
mkdir -p "$OUT"

grep -q "connect.ngrok-agent.com" /etc/hosts || \
  echo "127.0.0.1 connect.ngrok-agent.com" >> /etc/hosts

cat > "$OUT/ngrok_tls_server.py" <<'PY'
import socket, ssl
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain('/lab/src/scenarios/ngrok/assets/ngrok_cert.pem',
                    '/lab/src/scenarios/ngrok/assets/ngrok_key.pem')
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 443))
s.listen(32)
while True:
    try:
        c, _ = s.accept()
        try:
            ctx.wrap_socket(c, server_side=True).close()
        except Exception:
            c.close()
    except Exception:
        break
PY

python3 "$OUT/ngrok_tls_server.py" > "$OUT/ngrok_srv.log" 2>&1 &
SRV=$!
sleep 1

timeout 30 /lab/bin/tools/ngrok/ngrok http 8080 --log stdout \
  > "$OUT/ngrok_client.log" 2>&1
RC=$?
kill "$SRV" 2>/dev/null
echo "ngrok scenario rc=$RC" >> "$OUT/ngrok.log"
exit 0
