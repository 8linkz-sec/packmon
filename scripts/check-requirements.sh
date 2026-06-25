#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE="full"
TARGET=""
REQUIREMENTS_PATH="$ROOT_DIR/requirements/packmon-tools.tsv"

usage() {
  cat <<'EOF'
Usage: scripts/check-requirements.sh [--profile agent|web|full|sbom|server|dev] [--target PATH]
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)
      PROFILE="${2:-}"
      shift 2
      ;;
    --target)
      TARGET="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

case "$PROFILE" in
  agent|web|full|sbom|server|dev) ;;
  *)
    echo "invalid profile: $PROFILE" >&2
    usage >&2
    exit 2
    ;;
esac

in_profile() {
  local profiles="$1"
  [[ ",$profiles," == *",$PROFILE,"* ]]
}

numeric_version() {
  printf '%s\n' "$1" | sed -E 's/^[^0-9]*([0-9]+(\.[0-9]+){0,2}).*$/\1/'
}

version_ge() {
  local found required
  found="$(numeric_version "$1")"
  required="$(numeric_version "$2")"
  local f1=0 f2=0 f3=0 r1=0 r2=0 r3=0
  IFS=. read -r f1 f2 f3 <<< "$found"
  IFS=. read -r r1 r2 r3 <<< "$required"
  f1="${f1:-0}"; f2="${f2:-0}"; f3="${f3:-0}"
  r1="${r1:-0}"; r2="${r2:-0}"; r3="${r3:-0}"
  if (( f1 > r1 )); then return 0; fi
  if (( f1 < r1 )); then return 1; fi
  if (( f2 > r2 )); then return 0; fi
  if (( f2 < r2 )); then return 1; fi
  (( f3 >= r3 ))
}

tool_version() {
  local command="$1"
  local resolved="$2"
  case "$command" in
    go) go version 2>/dev/null | head -n 1 ;;
    node) node --version 2>/dev/null | head -n 1 ;;
    npm) npm --version 2>/dev/null | head -n 1 ;;
    python) python --version 2>&1 | head -n 1 ;;
    mvn) mvn --version 2>/dev/null | head -n 1 ;;
    docker) docker --version 2>/dev/null | head -n 1 ;;
    packmon) "$resolved" version 2>/dev/null | head -n 1 || true ;;
    cyclonedx-gomod) cyclonedx-gomod version 2>/dev/null | head -n 1 || true ;;
    gofumpt) gofumpt -version 2>/dev/null | head -n 1 || true ;;
    *) "$command" --version 2>/dev/null | head -n 1 || true ;;
  esac
}

resolve_packmon_command() {
  if command -v packmon >/dev/null 2>&1; then
    command -v packmon
    return
  fi
  for candidate in ./packmon ./packmon.exe "$ROOT_DIR/.build/packmon" "$ROOT_DIR/.build/packmon.exe"; do
    if [[ -f "$candidate" && -x "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return
    fi
  done
}

resolve_requirement_command() {
  local command="$1"
  if [[ "$command" == "packmon" ]]; then
    resolve_packmon_command
    return
  fi
  command -v "$command" 2>/dev/null || true
}

detect_sbom_ids() {
  local target="$1"
  if [[ ! -e "$target" ]]; then
    echo "target does not exist: $target" >&2
    exit 1
  fi

  find "$target" \
    \( -type d \( -name .git -o -name node_modules -o -name vendor -o -name __pycache__ -o -name .build -o -name .gotmp \) -prune \) \
    -o -type f -print |
    while IFS= read -r file; do
      case "$(basename "$file" | tr '[:upper:]' '[:lower:]')" in
        go.mod)
          printf '%s\n' go cyclonedx-gomod
          ;;
        package-lock.json|npm-shrinkwrap.json|pnpm-lock.yaml|yarn.lock|package.json)
          printf '%s\n' node npm cyclonedx-npm
          ;;
        requirements.txt|pyproject.toml|poetry.lock|pipfile|pipfile.lock)
          printf '%s\n' python cyclonedx-py
          ;;
        pom.xml)
          printf '%s\n' mvn
          ;;
      esac
    done | sort -u
}

target_ids=""
if [[ "$PROFILE" == "sbom" && -n "$TARGET" ]]; then
  target_ids="$(detect_sbom_ids "$TARGET")"
  if [[ -z "$target_ids" ]]; then
    echo "No auto-SBOM generator requirements detected under '$TARGET'."
    echo "Packmon can still scan native lockfiles and existing SBOMs without extra tools."
    exit 0
  fi
  echo "Detected $(printf '%s\n' "$target_ids" | sed '/^$/d' | wc -l | tr -d ' ') auto-SBOM requirement group(s) under '$TARGET'."
fi

target_contains_id() {
  local id="$1"
  [[ -z "$target_ids" ]] && return 0
  printf '%s\n' "$target_ids" | grep -Fxq "$id"
}

failures=0
checked=0

while IFS='|' read -r id command profiles required version installer install_hint purpose; do
  if [[ -z "${id:-}" || "$id" == \#* ]]; then
    continue
  fi
  if ! in_profile "$profiles"; then
    continue
  fi
  if ! target_contains_id "$id"; then
    continue
  fi

  checked=$((checked + 1))
  resolved_command="$(resolve_requirement_command "$command")"
  if [[ -z "$resolved_command" ]]; then
    printf 'missing  %-18s %s\n' "$command" "$install_hint"
    failures=$((failures + 1))
    continue
  fi

  version_text="$(tool_version "$command" "$resolved_command")"
  case "$command" in
    go|node|npm|python)
      if [[ "$version" != "any" ]] && ! version_ge "$version_text" "${version#>=}"; then
        printf 'wrong    %-18s found "%s", need %s\n' "$command" "$version_text" "$version"
        failures=$((failures + 1))
        continue
      fi
      ;;
  esac

  if [[ -n "$version_text" ]]; then
    printf 'ok       %-18s %s\n' "$command" "$version_text"
  else
    printf 'ok       %-18s found\n' "$command"
  fi
done < "$REQUIREMENTS_PATH"

if (( checked == 0 )); then
  echo "No requirements are defined for profile '$PROFILE'."
  exit 0
fi

if (( failures > 0 )); then
  echo
  echo "$failures requirement(s) missing or incompatible for profile '$PROFILE'." >&2
  if [[ "$PROFILE" == "sbom" && -n "$TARGET" ]]; then
    echo "Only tools required by the detected target manifests were checked." >&2
  fi
  echo "Run scripts/bootstrap for managed tools after installing missing base toolchains." >&2
  exit 1
fi

echo
echo "All requirements are available for profile '$PROFILE'."
