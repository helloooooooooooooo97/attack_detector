#!/bin/bash
# Normal-browsing baseline scenario (negative test).
set +e

OUT="${OUT:-/lab/src/out}"
mkdir -p "$OUT"
TC=/opt/tomcat

cp /lab/bin/extract_v4.0.7/server/default_aes/shell.jsp "$TC/webapps/ROOT/shell.jsp"
sed -i 's#</Service>#<Connector port="8443" protocol="org.apache.coyote.http11.Http11NioProtocol" SSLEnabled="true" scheme="https" secure="true" sslProtocol="TLS" keystoreFile="conf/keystore.jks" keystorePass="changeit" />\n  </Service>#' "$TC/conf/server.xml"
CATALINA_HOME="$TC" "$TC/bin/catalina.sh" start >/dev/null 2>&1

READY=0
for i in $(seq 1 60); do
  curl -sk -o /dev/null https://127.0.0.1:8443/
  if [ $? -eq 0 ]; then READY=1; break; fi
  sleep 1
done
echo "tomcat_ready=$READY" > "$OUT/normal.log"
sleep 2

cd /lab
mkdir -p /lab/classes
javac -encoding UTF-8 -cp /lab/bin/extract_v4.0.7/Behinder.jar -d /lab/classes \
  /lab/src/framework/drivers/NormalDriver.java >> "$OUT/normal.log" 2>&1

echo "== normal browsing (8 GETs) ==" >> "$OUT/normal.log"
java -cp /lab/classes:/lab/bin/extract_v4.0.7/Behinder.jar NormalDriver \
  https://127.0.0.1:8443/docs/ 8 >> "$OUT/normal.log" 2>&1

sleep 3
echo "normal scenario done" >> "$OUT/normal.log"
exit 0
