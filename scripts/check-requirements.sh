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

source "$ROOT_DIR/scripts/lib/requirements.sh"
parse_requirements_args "$@"
validate_profile "$PROFILE"
prepare_target_filter

failures=0
checked=0

while IFS='|' read -r id command profiles required version installer install_hint _purpose; do
  if ! requirement_applies "$id" "$profiles"; then
    continue
  fi

  checked=$((checked + 1))
  resolved_command="$(resolve_requirement_command "$command")"
  if [[ -z "$resolved_command" ]]; then
    printf 'missing  %-18s %s\n' "$command" "$install_hint"
    failures=$((failures + 1))
    continue
  fi

  version_text="$(tool_version "$command" "$resolved_command" "$installer")"
  if [[ "$version" != "any" ]]; then
    if [[ "$installer" != "manual" ]]; then
      if ! version_eq "$version_text" "$version"; then
        printf 'wrong    %-18s found "%s", need pinned %s\n' "$command" "$version_text" "$version"
        failures=$((failures + 1))
        continue
      fi
    else
      case "$command" in
        go|node|npm|python|mvn)
          if ! version_ge "$version_text" "${version#>=}"; then
            printf 'wrong    %-18s found "%s", need %s\n' "$command" "$version_text" "$version"
            failures=$((failures + 1))
            continue
          fi
          if [[ "$command" == "mvn" ]]; then
            java_version="$(maven_java_version "$resolved_command")"
            if ! version_ge "$java_version" "17"; then
              printf 'wrong    %-18s Maven uses Java "%s", need JDK >=17\n' "$command" "${java_version:-unknown}"
              failures=$((failures + 1))
              continue
            fi
          fi
          ;;
      esac
    fi
  fi

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
