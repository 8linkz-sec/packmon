#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
status=0

is_checked_file() {
  case "$1" in
    *.go|internal/web/static/tailwind.css|internal/web/static/htmx.min.js|docs/vendor/*)
      return 1
      ;;
    .editorconfig|.env.example|.gitattributes|.gitignore|.golangci.yml|.npmrc|Dockerfile|Makefile)
      return 0
      ;;
    *.css|*.html|*.js|*.json|*.mjs|*.md|*.ps1|*.sh|*.sql|*.yaml|*.yml)
      return 0
      ;;
  esac
  return 1
}

check_file() {
  local rel="$1"
  local path="$ROOT_DIR/$rel"
  [[ -f "$path" ]] || return 0

  if grep -Iq . "$path"; then
    :
  else
    return 0
  fi

  if grep -q $'\r' "$path"; then
    echo "$rel: contains CRLF or bare CR line endings" >&2
    status=1
  fi
  if grep -n '[[:blank:]]$' "$path"; then
    echo "$rel: contains trailing whitespace" >&2
    status=1
  fi
  if [[ -s "$path" ]] && [[ "$(tail -c 1 "$path")" != "" ]]; then
    echo "$rel: missing final newline" >&2
    status=1
  fi
}

while IFS= read -r rel; do
  if is_checked_file "$rel"; then
    check_file "$rel"
  fi
done < <(git -C "$ROOT_DIR" ls-files)

exit "$status"
