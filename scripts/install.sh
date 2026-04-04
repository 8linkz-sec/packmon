#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="${PACKMON_INSTALL_PREFIX:-$HOME/.packmon/bin}"
BUILD_DIR="${PACKMON_BUILD_DIR:-$ROOT_DIR/.build}"

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

mkdir -p "$PREFIX" "$BUILD_DIR"
require_command go

echo "Building packmon binaries..."
(
  cd "$ROOT_DIR"
  go build -o "$BUILD_DIR/packmon" ./cmd/packmon
  go build -o "$BUILD_DIR/packmon-server" ./cmd/packmon-server
)

install -m 0755 "$BUILD_DIR/packmon" "$PREFIX/packmon"
install -m 0755 "$BUILD_DIR/packmon-server" "$PREFIX/packmon-server"

mkdir -p "$HOME/.packmon/db" "$HOME/.packmon/config"

cat <<EOF
Installed:
  $PREFIX/packmon
  $PREFIX/packmon-server

Suggested next steps:
  export PATH="$PREFIX:\$PATH"
  packmon version
  packmon db info
EOF
