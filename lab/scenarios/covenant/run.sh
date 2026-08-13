#!/bin/bash
# Covenant scenario: real Covenant server (patched for Linux: libssl1.1,
# grunt template indentation, RSA.Create, Tls12, missing stager/executor
# csproj) + a real linux-arm64 grunt generated through the REST API.
set +e
OUT="${OUT:-/lab/src/out}"
mkdir -p "$OUT"
cd /opt/covenant-build

./Covenant -u admin -p "Password123!" > "$OUT/covenant_svr.log" 2>&1 &
SVR=$!
for i in $(seq 1 90); do
  curl -sk -o /dev/null https://127.0.0.1:7443/api/users/current && break
  sleep 1
done

TOKEN=$(curl -sk -X POST https://127.0.0.1:7443/api/users/login \
  -H "Content-Type: application/json" \
  -d '{"userName":"admin","password":"Password123!"}' \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['covenantToken'])")
AUTH="Authorization: Bearer $TOKEN"

curl -sk -X POST https://127.0.0.1:7443/api/listeners/http -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{"name":"lab","description":"lab","bindAddress":"0.0.0.0","bindPort":8080,
       "connectAddresses":["127.0.0.1"],"connectPort":8080,"profileId":1,
       "listenerTypeId":1,"status":1,"useSSL":false}' > /dev/null

curl -sk -X PUT https://127.0.0.1:7443/api/launchers/binary -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{"listenerId":1,"implantTemplateId":1,"name":"labgrunt",
       "dotNetVersion":"NetCore31","runtimeIdentifier":"linux_arm64",
       "delay":3,"jitterPercent":0,"outputKind":"ConsoleApplication",
       "killDate":"2027-01-01T00:00:00"}' > /dev/null

curl -sk -X POST https://127.0.0.1:7443/api/launchers/binary -H "$AUTH" \
  -H "Content-Type: application/json" > /dev/null

GRUNT=Data/Grunt/GruntHTTP/GruntHTTPStager/bin/Release/netcoreapp3.1/linux-arm64/publish/GruntHTTPStager
if [ -x "$GRUNT" ]; then
  ./$GRUNT > "$OUT/covenant_grunt.log" 2>&1 &
  GP=$!
  sleep 55
  kill "$GP" 2>/dev/null
fi
kill "$SVR" 2>/dev/null
echo "covenant scenario done" >> "$OUT/covenant.log"
exit 0
