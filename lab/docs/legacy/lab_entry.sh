#!/bin/bash
set -euo pipefail

OUT=/lab/src/out
mkdir -p "$OUT"
TC=/opt/tomcat
SHELL_SRC=/lab/bin/extract_v4.0.7/server/default_aes/shell.jsp

# Behinder reads data.db (SQLite, holds the trans-protocol definitions) from
# the working directory; /lab/bin is mounted read-only, so copy it locally.
cp /lab/bin/extract_v4.0.7/data.db /lab/data.db

# Deploy the default file-based webshell
cp "$SHELL_SRC" "$TC/webapps/ROOT/shell.jsp"

# Memory-shell-like variant: the server forces Connection: close after every
# request-response, so the client must open a new TCP connection per operation.
sed '2i <% response.setHeader("Connection","close"); %>' "$SHELL_SRC" > "$TC/webapps/ROOT/shell_close.jsp"

# Enable an HTTPS connector on 8443
sed -i 's#</Service>#<Connector port="8443" protocol="org.apache.coyote.http11.Http11NioProtocol" SSLEnabled="true" scheme="https" secure="true" sslProtocol="TLS" keystoreFile="conf/keystore.jks" keystorePass="changeit" />\n  </Service>#' "$TC/conf/server.xml"

# Start Tomcat and wait for the HTTPS port
CATALINA_HOME="$TC" "$TC/bin/catalina.sh" start >/dev/null 2>&1
HTTP_READY=0
for i in $(seq 1 90); do
  if curl -sk -o /dev/null https://127.0.0.1:8443/; then
    HTTP_READY=1
    break
  fi
  sleep 1
done
sleep 2

cd /lab        # data.db must be in the working directory

# compile the headless driver against the real Behinder client jar
javac -encoding UTF-8 -cp /lab/bin/extract_v4.0.7/Behinder.jar -d /lab /lab/src/Driver.java

# diagnostics
{
  echo "HTTP_READY=$HTTP_READY"
  java -version 2>&1
  curl -sk -o /dev/null -w 'root_https_status=%{http_code}\n' https://127.0.0.1:8443/
  curl -sk -o /dev/null -w 'shell_https_status=%{http_code}\n' https://127.0.0.1:8443/shell.jsp
} > "$OUT/diagnostics.txt" 2>&1 || true
tail -30 "$TC/logs/catalina.out" > "$OUT/tomcat.log" 2>/dev/null || true

# ---- Scenario A: file-based webshell (Tomcat keep-alive) ----
tcpdump -i lo -s 0 -w "$OUT/cap_keepalive.pcap" 'tcp port 8443' >/dev/null 2>&1 &
TCPID=$!
sleep 1
java -cp /lab:/lab/bin/extract_v4.0.7/Behinder.jar Driver https://127.0.0.1:8443/shell.jsp rebeyond jsp 9 \
  > "$OUT/driver_keepalive.log" 2>&1 || true
sleep 8   # capture the keep-alive idle window (connection pool holds sockets)
kill "$TCPID" 2>/dev/null || true
sleep 1

# ---- Scenario B: memory-shell-like webshell (Connection: close) ----
tcpdump -i lo -s 0 -w "$OUT/cap_close.pcap" 'tcp port 8443' >/dev/null 2>&1 &
TCPID=$!
sleep 1
java -cp /lab:/lab/bin/extract_v4.0.7/Behinder.jar Driver https://127.0.0.1:8443/shell_close.jsp rebeyond jsp 9 \
  > "$OUT/driver_close.log" 2>&1 || true
sleep 3
kill "$TCPID" 2>/dev/null || true

# ---- Scenario C: baseline normal browsing (same TLS stack, plain GETs) ----
javac -encoding UTF-8 -cp /lab/bin/extract_v4.0.7/Behinder.jar -d /lab /lab/src/NormalDriver.java
tcpdump -i lo -s 0 -w "$OUT/cap_normal.pcap" 'tcp port 8443' >/dev/null 2>&1 &
TCPID=$!
sleep 1
java -cp /lab:/lab/bin/extract_v4.0.7/Behinder.jar NormalDriver https://127.0.0.1:8443/docs/ 10 \
  > "$OUT/driver_normal.log" 2>&1 || true
sleep 5
kill "$TCPID" 2>/dev/null || true

"$TC/bin/catalina.sh" stop >/dev/null 2>&1 || true
echo "=== lab done ==="
ls -la "$OUT"
