#!/bin/bash
# Build the real XiebroC2 Linux TCP client with the teamserver's placeholder
# substitution (Host/Port/ListenerName), plus a minimal listener driver.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
XIE_SRC="${XIE_SRC:-/tmp/behinder_lab/tools/xiebro/src/ClientGo/Linux/TCP}"
OUT="${OUT:-$SCRIPT_DIR}"
GOOS="${GOOS:-linux}"
GOARCH="${GOARCH:-arm64}"

work="$(mktemp -d)"
cp -r "$XIE_SRC"/. "$work/"
cd "$work"
python3 - main.go <<'PY'
import os, sys
path = sys.argv[1]
src = open(path, encoding="utf-8").read()
src = src.replace('Host := "HostAAAABBBBCCCCDDDD"', f'Host := "{os.environ["XIE_HOST"]}"')
src = src.replace('Port := "PortAAAABBBBCCCCDDDD"', f'Port := "{os.environ["XIE_PORT"]}"')
src = src.replace('ListenerName := "ListenNameAAAABBBBCCCCDDDD"', f'ListenerName := "{os.environ["XIE_LISTENER"]}"')
open(path, "w", encoding="utf-8").write(src)
PY
GOOS=$GOOS GOARCH=$GOARCH CGO_ENABLED=0 go mod tidy >/dev/null 2>&1 || true
GOOS=$GOOS GOARCH=$GOARCH CGO_ENABLED=0 go build -mod=mod -ldflags="-s -w" -o "$OUT/xiebro-client" .
echo "built $OUT/xiebro-client"

cd "$SCRIPT_DIR"
GOOS=$GOOS GOARCH=$GOARCH CGO_ENABLED=0 go build -o "$OUT/xiebro-driver" .
echo "built $OUT/xiebro-driver"
rm -rf "$work"
