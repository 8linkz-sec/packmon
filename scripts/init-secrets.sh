#!/usr/bin/env bash
# Generate or complete the local .env via the init-secrets Compose service,
# running the container as the owner of this checkout. On native Linux the
# image's packmon system account cannot write the bind-mounted checkout or
# read an existing owner-only .env; matching the host user keeps .env owned
# by you with mode 0600.
#
# Usage (from anywhere): bash scripts/init-secrets.sh
# Explicit PACKMON_UID / PACKMON_GID in the environment always win.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# Rootless Docker maps container root (0:0) to the invoking host user, while
# the host UID/GID inside the container would map to an unprivileged sub-UID.
# Capture the output first so `pipefail` cannot turn a closed pipe into a
# false negative; an unreachable daemon falls back to the host IDs.
security_options="$(docker info --format '{{.SecurityOptions}}' 2>/dev/null || true)"
if [[ "$security_options" == *rootless* ]]; then
  default_uid=0
  default_gid=0
else
  default_uid="$(id -u)"
  default_gid="$(id -g)"
fi

PACKMON_UID="${PACKMON_UID:-$default_uid}"
PACKMON_GID="${PACKMON_GID:-$default_gid}"
export PACKMON_UID PACKMON_GID

docker compose run --rm init-secrets
