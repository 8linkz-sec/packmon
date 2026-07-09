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

source "$ROOT_DIR/scripts/lib/requirements.sh"
parse_requirements_args "$@"
validate_profile "$PROFILE"
prepare_target_filter

require_command() {
  local command="$1"
  local for_tool="$2"
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "$for_tool requires '$command' first. Install the base toolchain and rerun bootstrap." >&2
    exit 1
  fi
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
      echo "installing $command with npm install --global --ignore-scripts $package"
      npm install --global --ignore-scripts "$package"
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

while IFS='|' read -r id command profiles required version installer install_hint _purpose; do
  if ! requirement_applies "$id" "$profiles"; then
    continue
  fi

  checked=$((checked + 1))
  resolved_command="$(resolve_requirement_command "$command")"
  if [[ -n "$resolved_command" ]] && requirement_satisfied "$command" "$version" "$installer" "$resolved_command"; then
    echo "already available: $command"
    continue
  fi
  if [[ "$installer" == "manual" ]]; then
    manual_requirements+=("$command|$install_hint")
    continue
  fi
  if [[ -n "$resolved_command" && "$version" != "any" ]]; then
    version_text="$(tool_version "$command" "$resolved_command" "$installer")"
    echo "upgrading $command from ${version_text:-unknown} to pinned $version"
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
