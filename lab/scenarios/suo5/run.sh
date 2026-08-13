#!/bin/bash
set +e
OUT="${OUT:-/lab/src/out}"
mkdir -p "$OUT"
TC=/opt/tomcat

cp /lab/bin/tools/suo5/src/assets/java/suo5.jsp "$TC/webapps/ROOT/suo5.jsp"
sed -i 's#</Service>#<Connector port="8443" protocol="org.apache.coyote.http11.Http11NioProtocol" SSLEnabled="true" scheme="https" secure="true" sslProtocol="TLS" keystoreFile="conf/keystore.jks" keystorePass="changeit" />\n  </Service>#' "$TC/conf/server.xml"
CATALINA_HOME="$TC" "$TC/bin/catalina.sh" start >/dev/null 2>&1
READY=0
for i in $(seq 1 60); do
  curl -sk -o /dev/null https://127.0.0.1:8443/suo5.jsp && READY=1 && break
  sleep 1
done
echo "tomcat_ready=$READY" > "$OUT/suo5.log"
sleep 2

cp /lab/bin/tools/suo5/suo5 /tmp/suo5 && chmod +x /tmp/suo5
for round in 1 2 3; do
  /tmp/suo5 -t https://127.0.0.1:8443/suo5.jsp -l 127.0.0.1:1111 -d \
    > "$OUT/suo5_client.log" 2>&1 &
  PID=$!
  sleep 11
  kill "$PID" 2>/dev/null
  sleep 3
done
echo "suo5 scenario done" >> "$OUT/suo5.log"
exit 0
