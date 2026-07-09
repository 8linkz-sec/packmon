#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$ROOT_DIR"

new_local_secret() {
  local bytes="${1:-32}"
  dd if=/dev/urandom bs="$bytes" count=1 2>/dev/null | base64 | tr -d '\n'
  printf '\n'
}

env_value() {
  local key="$1"
  awk -F= -v key="$key" '$1 == key { print substr($0, index($0, "=") + 1); exit }' .env
}

missing_env_value() {
  local value="${1-}"
  [[ -z "${value//[[:space:]]/}" || "$value" == '""' || "$value" == "''" ]]
}

append_missing_env_example_defaults() {
  local tmp
  tmp="$(mktemp)"
  awk '
    function trim(value) {
      sub(/^[[:space:]]+/, "", value)
      sub(/[[:space:]]+$/, "", value)
      return value
    }
    function secret_key(key) {
      return key == "POSTGRES_PASSWORD" ||
        key == "PACKMON_DB_PASSWORD" ||
        key == "PACKMON_ADMIN_INITIAL_PASSWORD" ||
        key == "PACKMON_ENCRYPTION_KEY" ||
        key == "PACKMON_ADMIN_AUDIT_HMAC_KEY"
    }
    BEGIN {
      while ((getline line < ".env") > 0) {
        raw = trim(line)
        if (raw == "" || raw ~ /^#/ || index(raw, "=") == 0) {
          continue
        }
        key = trim(substr(raw, 1, index(raw, "=") - 1))
        if (key != "") {
          existing[key] = 1
        }
      }
    }
    {
      raw = trim($0)
      if (raw == "" || raw ~ /^#/ || index(raw, "=") == 0) {
        next
      }
      key = trim(substr(raw, 1, index(raw, "=") - 1))
      if (key == "" || existing[key] || secret_key(key)) {
        next
      }
      print $0
      existing[key] = 1
    }
  ' .env.example > "$tmp"

  if [[ ! -s "$tmp" ]]; then
    rm -f "$tmp"
    return 1
  fi

  {
    printf '\n# Added from .env.example for current local stack defaults.\n'
    while IFS= read -r line; do
      printf '%s\n' "$line"
    done < "$tmp"
  } >> .env
  rm -f "$tmp"
  return 0
}

set_env_value() {
  local key="$1"
  local value="$2"
  local tmp
  tmp="$(mktemp)"
  awk -v key="$key" -v value="$value" '
    BEGIN { done = 0 }
    $0 ~ "^[[:space:]]*" key "[[:space:]]*=" {
      print key "=" value
      done = 1
      next
    }
    { print }
    END {
      if (!done) {
        print key "=" value
      }
    }
  ' .env > "$tmp"
  mv "$tmp" .env
}

initialize_local_env() {
  local changed=0

  if [[ ! -f .env ]]; then
    cp .env.example .env
    changed=1
  fi

  if append_missing_env_example_defaults; then
    changed=1
  fi

  local postgres_password
  local packmon_db_password
  local database_password
  postgres_password="$(env_value POSTGRES_PASSWORD)"
  packmon_db_password="$(env_value PACKMON_DB_PASSWORD)"

  if ! missing_env_value "$postgres_password"; then
    database_password="$postgres_password"
  elif ! missing_env_value "$packmon_db_password"; then
    database_password="$packmon_db_password"
  else
    database_password="$(new_local_secret 32)"
  fi

  if missing_env_value "$postgres_password"; then
    set_env_value POSTGRES_PASSWORD "$database_password"
    changed=1
  fi
  if missing_env_value "$packmon_db_password"; then
    set_env_value PACKMON_DB_PASSWORD "$database_password"
    changed=1
  fi
  if missing_env_value "$(env_value PACKMON_ADMIN_INITIAL_PASSWORD)"; then
    set_env_value PACKMON_ADMIN_INITIAL_PASSWORD "$(new_local_secret 24)"
    changed=1
  fi
  if missing_env_value "$(env_value PACKMON_ENCRYPTION_KEY)"; then
    set_env_value PACKMON_ENCRYPTION_KEY "$(new_local_secret 32)"
    changed=1
  fi
  if missing_env_value "$(env_value PACKMON_ADMIN_AUDIT_HMAC_KEY)"; then
    set_env_value PACKMON_ADMIN_AUDIT_HMAC_KEY "$(new_local_secret 32)"
    changed=1
  fi

  if [[ "$changed" -eq 1 ]]; then
    echo "Created or updated .env with generated local-only secrets."
    echo "Generated secret values are not printed; use .env for the first admin login" \
      "and review it before shared or production use."
  fi
}

local_stack_server_port() {
  local port="${PACKMON_SERVER_PORT:-}"
  if missing_env_value "$port"; then
    port="$(env_value PACKMON_SERVER_PORT)"
  fi
  if missing_env_value "$port"; then
    port=8080
  fi
  port="${port#\"}"
  port="${port%\"}"
  port="${port#\'}"
  port="${port%\'}"
  printf '%s\n' "$port"
}

probe_ready_url() {
  local url="$1"
  local server_port="$2"

  if command -v curl >/dev/null 2>&1; then
    curl -fsS --max-time 2 "$url" >/dev/null
  elif command -v wget >/dev/null 2>&1; then
    wget -q -T 2 -O /dev/null "$url"
  else
    docker compose exec -T packmon-server \
      wget -qO- "http://127.0.0.1:${server_port}/readyz" >/dev/null 2>&1
  fi
}

print_local_stack_diagnostics() {
  echo "Docker Compose status:" >&2
  docker compose ps >&2 || true
  echo >&2
  echo "Recent packmon-server logs:" >&2
  docker compose logs --tail=120 packmon-server >&2 || true
}

wait_local_stack_ready() {
  local server_port="$1"
  local timeout_seconds="${2:-120}"
  local ready_url="http://127.0.0.1:${server_port}/readyz"
  local deadline=$((SECONDS + timeout_seconds))

  echo "Waiting for Packmon readiness at ${ready_url}..."
  while ((SECONDS < deadline)); do
    if probe_ready_url "$ready_url" "$server_port"; then
      return 0
    fi
    sleep 2
  done

  echo "Packmon server did not become ready at ${ready_url} within ${timeout_seconds} seconds." >&2
  print_local_stack_diagnostics
  return 1
}

initialize_local_env
server_port="$(local_stack_server_port)"

echo "Preparing Packmon database..."
docker compose run --build --rm packmon-migrate

echo "Starting Packmon local Docker stack..."
docker compose up --build -d

wait_local_stack_ready "$server_port" 120

echo
echo "Packmon local server: http://localhost:${server_port}"
echo "Admin login:          http://localhost:${server_port}/admin/login"
