#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:-${PACKMON_VERSION:-}}"
PREFIX="${PACKMON_INSTALL_PREFIX:-$HOME/.packmon/bin}"

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

if [ -z "$VERSION" ]; then
  echo "usage: scripts/install-release.sh <existing-release-tag>" >&2
  exit 1
fi

PACKMON_VERSION_REGEX='^v[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z][0-9A-Za-z.-]*)?$'
printf '%s\n' "$VERSION" | grep -Eq "$PACKMON_VERSION_REGEX" || {
  echo "release tag must look like v1.2.3" >&2
  exit 1
}

case "$(uname -s)" in
  Linux) OS=linux ;;
  Darwin) OS=darwin ;;
  *)
    echo "unsupported OS for release binary install: $(uname -s)" >&2
    exit 1
    ;;
esac

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *)
    echo "unsupported architecture for release binary install: $(uname -m)" >&2
    exit 1
    ;;
esac

require_command curl
require_command gh
if command -v sha256sum >/dev/null 2>&1; then
  CHECKSUM_CMD=(sha256sum -c)
else
  require_command shasum
  CHECKSUM_CMD=(shasum -a 256 -c)
fi

BINARY_NAME="packmon-${OS}-${ARCH}"
BINARY_BASE_URL="${PACKMON_BINARY_MIRROR:-https://github.com/8linkz-sec/packmon/releases/download/${VERSION}}"
BINARY_BASE_URL="${BINARY_BASE_URL%/}"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

curl -sfL "${BINARY_BASE_URL}/${BINARY_NAME}" -o "${TMP_DIR}/${BINARY_NAME}"
curl -sfL "${BINARY_BASE_URL}/checksums.txt" -o "${TMP_DIR}/checksums.txt"
grep -E "[[:space:]]${BINARY_NAME}$" "${TMP_DIR}/checksums.txt" > "${TMP_DIR}/${BINARY_NAME}.sha256"
(cd "$TMP_DIR" && "${CHECKSUM_CMD[@]}" "${BINARY_NAME}.sha256")

gh attestation verify "${TMP_DIR}/${BINARY_NAME}" \
  --repo 8linkz-sec/packmon \
  --signer-workflow 8linkz-sec/packmon/.github/workflows/release.yml \
  --source-ref "refs/tags/${VERSION}"

mkdir -p "$PREFIX"
install -m 0755 "${TMP_DIR}/${BINARY_NAME}" "$PREFIX/packmon"

echo "Installed verified Packmon release ${VERSION} to ${PREFIX}/packmon"
