#!/bin/bash
# Build the DeimosC2 TCP agent (real Deimos code, template placeholders
# substituted like the C2 server does) plus this listener driver.
#
# deimos src: /tmp/behinder_lab/tools/deimos/src (github.com/DeimosC2/DeimosC2)
# outputs:    deimos-agent, deimos-driver (linux/arm64)
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

DEIMOS_SRC="${DEIMOS_SRC:-/tmp/behinder_lab/tools/deimos/src}"
HOST="${AGENT_HOST:-127.0.0.1}"
PORT="${AGENT_PORT:-14000}"
DELAY="${AGENT_DELAY:-15.0}"
JITTER="${AGENT_JITTER:-0.0}"
OUT="${OUT:-$(pwd)}"
GOOS="${GOOS:-linux}"
GOARCH="${GOARCH:-arm64}"

work="$(mktemp -d)"
cp -r "$DEIMOS_SRC/agents/tcp" "$work/agent"
cp "$DEIMOS_SRC/go.mod" "$work/agent/go.mod"
cp "$DEIMOS_SRC/go.sum" "$work/agent/go.sum" 2>/dev/null || true

# substitute the template placeholders (same as the C2 server's gobuild step);
# the PEM public key keeps its real newlines inside the Go raw string.
PUBKEY="$(cat keys/pub.pem)"
python3 - "$work/agent/tcp_agent.go" <<'PY' > "$work/agent/tcp_agent.go.tmp"
import os, sys
path, host, port, delay, jitter, pubkey = (
    sys.argv[1], os.environ["AGENT_HOST"], os.environ["AGENT_PORT"],
    os.environ["AGENT_DELAY"], os.environ["AGENT_JITTER"],
    os.environ["DEIMOS_PUBKEY"],
)
src = open(path, encoding="utf-8").read()
src = src.replace('"{{HOST}}"', f'"{host}"')
src = src.replace('"{{PORT}}"', f'"{port}"')
src = src.replace("{{DELAY}}", delay)
src = src.replace("{{JITTER}}", jitter)
src = src.replace('"{{EOL}}"', '""')
src = src.replace('"{{LIVEHOURS}}"', '""')
src = src.replace("{{PUBKEY}}", pubkey)
sys.stdout.write(src)
PY
mv "$work/agent/tcp_agent.go.tmp" "$work/agent/tcp_agent.go"

# agent deps live under agents/resources + lib in the module root; make the
# module root available to the copied package.
mkdir -p "$work/root"
cp -r "$DEIMOS_SRC/agents" "$work/root/agents"
cp -r "$DEIMOS_SRC/lib" "$work/root/lib"
cp "$work/agent/go.mod" "$work/root/go.mod"
cp "$work/agent/go.sum" "$work/root/go.sum" 2>/dev/null || true
cp -r "$work/agent/tcp_agent.go" "$work/root/agents/tcp/tcp_agent.go"

cd "$work/root"
GOOS=$GOOS GOARCH=$GOARCH CGO_ENABLED=0 go build -mod=mod -o "$OUT/deimos-agent" ./agents/tcp
echo "built $OUT/deimos-agent"

cd "$SCRIPT_DIR"
GOOS=$GOOS GOARCH=$GOARCH CGO_ENABLED=0 go build -o "$OUT/deimos-driver" .
echo "built $OUT/deimos-driver"
rm -rf "$work"
