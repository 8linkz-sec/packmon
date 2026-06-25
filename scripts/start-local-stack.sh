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

  if [[ "$changed" -eq 1 ]]; then
    echo "Created or updated .env with generated local-only secrets."
    echo "Generated secret values are not printed; use .env for the first admin login and review it before shared or production use."
  fi
}

initialize_local_env

echo "Preparing Packmon database..."
docker compose run --build --rm packmon-migrate

echo "Starting Packmon local Docker stack..."
docker compose up --build -d

echo
echo "Packmon local server: http://localhost:8080"
echo "Admin login:          http://localhost:8080/admin/login"
