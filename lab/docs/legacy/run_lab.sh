#!/bin/bash
set -euo pipefail

LAB_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="${BEHINDER_BIN:-/tmp/behinder_lab}"
IMG="behinder-lab"

if [ ! -f "$BIN_DIR/extract_v4.0.7/Behinder.jar" ]; then
  echo "error: Behinder binaries not found at $BIN_DIR/extract_v4.0.7"
  echo "download and extract Behinder v4.0.7 zip there first"
  exit 1
fi

docker build -t "$IMG" -f "$LAB_DIR/Dockerfile" "$LAB_DIR"

mkdir -p "$LAB_DIR/out"

docker run --rm \
  -v "$BIN_DIR":/lab/bin:ro \
  -v "$LAB_DIR":/lab/src:rw \
  "$IMG" bash /lab/src/lab_entry.sh

echo "=== results in $LAB_DIR/out ==="
ls -la "$LAB_DIR/out"
