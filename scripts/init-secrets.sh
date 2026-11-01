#!/usr/bin/env bash
# Generate or complete the local .env via the init-secrets Compose service,
# running the container as the owner of this checkout. On native Linux the
# image's packmon system account cannot write the bind-mounted checkout or
# read an existing owner-only .env; matching the host UID/GID keeps .env owned
# by you with mode 0600.
#
# Usage (from anywhere): bash scripts/init-secrets.sh
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PACKMON_UID="$(id -u)"
PACKMON_GID="$(id -g)"
export PACKMON_UID PACKMON_GID

docker compose run --rm init-secrets
