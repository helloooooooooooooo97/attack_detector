#!/bin/bash
set +e
OUT="${OUT:-/lab/src/out}"
mkdir -p "$OUT" /lab/frp

cp /lab/bin/tools/frp/frps /tmp/frps && chmod +x /tmp/frps
cp /lab/bin/tools/frp/frpc /tmp/frpc && chmod +x /tmp/frpc

cat > /lab/frp/frps.toml <<'EOF'
bindPort = 7000
EOF
cat > /lab/frp/frpc.toml <<'EOF'
serverAddr = "127.0.0.1"
serverPort = 7000

[transport.tls]
enable = true

[[proxies]]
name = "lab"
type = "tcp"
localIP = "127.0.0.1"
localPort = 8080
remotePort = 7001
EOF

/tmp/frps -c /lab/frp/frps.toml > "$OUT/frp_svr.log" 2>&1 &
SVR=$!
sleep 2
/tmp/frpc -c /lab/frp/frpc.toml > "$OUT/frp_cli.log" 2>&1 &
CLI=$!
sleep 65
kill "$CLI" "$SVR" 2>/dev/null
echo "frp scenario done" >> "$OUT/frp.log"
exit 0
