#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE="full"
TARGET=""
REQUIREMENTS_PATH="$ROOT_DIR/requirements/packmon-tools.tsv"
CHECK_SCRIPT="$ROOT_DIR/scripts/check-requirements.sh"

usage() {
  cat <<'EOF'
Usage: scripts/bootstrap.sh [--profile agent|web|full|sbom|server|dev] [--target PATH]
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

require_command() {
  local command="$1"
  local for_tool="$2"
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "$for_tool requires '$command' first. Install the base toolchain and rerun bootstrap." >&2
    exit 1
  fi
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

install_managed_tool() {
  local command="$1"
  local installer="$2"
  case "$installer" in
    go-install:*)
      require_command go "$command"
      local module="${installer#go-install:}"
      echo "installing $command with go install $module"
      go install "$module"
      ;;
    npm-global:*)
      require_command npm "$command"
      local package="${installer#npm-global:}"
      echo "installing $command with npm install --global $package"
      npm install --global "$package"
      ;;
    pip-user:*)
      require_command python "$command"
      local package="${installer#pip-user:}"
      echo "installing $command with python -m pip install --user $package"
      python -m pip install --user "$package"
      ;;
    *)
      echo "$command is a base requirement and cannot be bootstrapped automatically." >&2
      exit 1
      ;;
  esac
}

manual_requirements=()
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
  if [[ -n "$(resolve_requirement_command "$command")" ]]; then
    echo "already available: $command"
    continue
  fi
  if [[ "$installer" == "manual" ]]; then
    manual_requirements+=("$command|$install_hint")
    continue
  fi
  install_managed_tool "$command" "$installer"
done < "$REQUIREMENTS_PATH"

if (( checked == 0 )); then
  echo "No requirements are defined for profile '$PROFILE'."
  exit 0
fi

if (( ${#manual_requirements[@]} > 0 )); then
  echo
  echo "Install these base requirements manually, then rerun bootstrap:" >&2
  for requirement in "${manual_requirements[@]}"; do
    IFS='|' read -r command install_hint <<< "$requirement"
    printf '  %-12s %s\n' "$command" "$install_hint" >&2
  done
  exit 1
fi

if [[ -n "$TARGET" ]]; then
  "$CHECK_SCRIPT" --profile "$PROFILE" --target "$TARGET"
else
  "$CHECK_SCRIPT" --profile "$PROFILE"
fi
