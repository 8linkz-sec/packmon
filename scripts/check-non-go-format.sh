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

  # -U keeps the CR visible to grep under Git Bash, whose grep otherwise strips
  # it in text mode; GNU grep on Linux ignores the flag.
  if grep -Uq $'\r' "$path"; then
    case "$rel" in
      *.ps1)
        # .gitattributes checks PowerShell scripts out with CRLF
        # (`*.ps1 text eol=crlf`): consistent CRLF is accepted, a bare CR or a
        # mix of CRLF and LF lines is not.
        if grep -Uqv $'^[^\r]*\r$' "$path"; then
          echo "$rel: contains bare CR or mixed line endings" >&2
          status=1
        fi
        ;;
      *)
        echo "$rel: contains CRLF or bare CR line endings" >&2
        status=1
        ;;
    esac
  fi
  # The optional CR catches trailing whitespace before a CRLF line ending.
  if grep -Un $'[[:blank:]]\r\{0,1\}$' "$path"; then
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
