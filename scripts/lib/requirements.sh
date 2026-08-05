#!/usr/bin/env bash

: "${ROOT_DIR:?ROOT_DIR must be set before sourcing scripts/lib/requirements.sh}"

AUTO_SBOM_MANIFESTS_PATH="$ROOT_DIR/internal/sbomgen/auto_sbom_manifests.tsv"

parse_requirements_args() {
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
}

validate_profile() {
  local profile="$1"
  case "$profile" in
    agent|web|full|sbom|server|dev) ;;
    *)
      echo "invalid profile: $profile" >&2
      usage >&2
      exit 2
      ;;
  esac
}

in_profile() {
  local profiles="$1"
  [[ ",$profiles," == *",$PROFILE,"* ]]
}

numeric_version() {
  printf '%s\n' "$1" | sed -E 's/^[^0-9]*([0-9]+(\.[0-9]+){0,2}).*$/\1/'
}

normalized_version() {
  local version="${1:-}"
  version="$(numeric_version "$version")"
  [[ -n "$version" ]] || return 1
  local v1=0 v2=0 v3=0
  IFS=. read -r v1 v2 v3 <<< "$version"
  printf '%s.%s.%s\n' "${v1:-0}" "${v2:-0}" "${v3:-0}"
}

version_eq() {
  local found required
  found="$(normalized_version "$1")" || return 1
  required="$(normalized_version "$2")" || return 1
  [[ "$found" == "$required" ]]
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

go_binary_module_version() {
  local resolved="$1"
  [[ -n "$resolved" ]] || return 0
  command -v go >/dev/null 2>&1 || return 0
  go version -m "$resolved" 2>/dev/null | awk '$1 == "mod" && NF >= 3 { print $3; exit }'
}

tool_version() {
  local command="$1"
  local resolved="$2"
  local installer="${3:-}"
  if [[ "$installer" == go-install:* ]]; then
    local module_version
    module_version="$(go_binary_module_version "$resolved")"
    if [[ -n "$module_version" ]]; then
      printf '%s\n' "$module_version"
      return
    fi
  fi
  case "$command" in
    go) go version 2>/dev/null | head -n 1 ;;
    node) node --version 2>/dev/null | head -n 1 ;;
    npm) npm --version 2>/dev/null | head -n 1 ;;
    python) python --version 2>&1 | head -n 1 ;;
    mvn) mvn --version 2>/dev/null | head -n 1 ;;
    docker) docker compose version 2>/dev/null | head -n 1 ;;
    packmon) "$resolved" version 2>/dev/null | head -n 1 || true ;;
    cyclonedx-gomod) cyclonedx-gomod version 2>/dev/null | head -n 1 || true ;;
    gofumpt) gofumpt -version 2>/dev/null | head -n 1 || true ;;
    *) "$command" --version 2>/dev/null | head -n 1 || true ;;
  esac
}

maven_java_version() {
  local resolved="${1:-mvn}"
  "$resolved" --version 2>/dev/null |
    awk -F'[:, ]+' '/^Java version:/ {
      for (i = 1; i <= NF; i++) {
        if ($i ~ /^[0-9]+(\.[0-9]+){0,2}/) {
          print $i
          exit
        }
      }
    }'
}

maven_java_satisfied() {
  local resolved="$1"
  local java_version
  java_version="$(maven_java_version "$resolved")"
  version_ge "$java_version" "17"
}

is_poetry_pyproject_for_requirements() {
  local file="$1"
  awk '
    /^[[:space:]]*\[/ {
      in_poetry = ($0 ~ /^[[:space:]]*\[tool\.poetry\][[:space:]]*($|#)/)
      in_deps = ($0 ~ /^[[:space:]]*\[tool\.poetry\.dependencies\][[:space:]]*($|#)/)
      next
    }
    in_poetry && /^[[:space:]]*name[[:space:]]*=/ { found = 1 }
    in_deps && /^[[:space:]]*[^#[:space:]][^=]*=/ { found = 1 }
    END { exit found ? 0 : 1 }
  ' "$file"
}

emit_auto_sbom_requirement_ids_for_manifest() {
  local file="$1"
  local name="$2"
  local dir="$3"
  local manifest kind ecosystem input_kind ids

  while IFS='|' read -r manifest kind ecosystem input_kind ids; do
    [[ -n "${manifest:-}" ]] || continue
    [[ "$manifest" != \#* ]] || continue
    [[ "$name" == "$manifest" ]] || continue

    case "$kind" in
      detect)
        if [[ "$manifest" == "package.json" ]] &&
          { [[ -f "$dir/pnpm-lock.yaml" ]] || [[ -f "$dir/yarn.lock" ]]; } &&
          [[ ! -f "$dir/package-lock.json" && ! -f "$dir/npm-shrinkwrap.json" ]]; then
          return 0
        fi
        tr ',' '\n' <<< "$ids"
        return 0
        ;;
      poetry-pyproject)
        if is_poetry_pyproject_for_requirements "$file"; then
          tr ',' '\n' <<< "$ids"
        fi
        return 0
        ;;
      support-file|unsupported)
        return 0
        ;;
      *)
        echo "unsupported auto-SBOM manifest kind '$kind' for '$manifest'" >&2
        exit 1
        ;;
    esac
  done < "$AUTO_SBOM_MANIFESTS_PATH"
}

detect_sbom_ids() {
  local target="$1"
  if [[ ! -e "$target" ]]; then
    echo "target does not exist: $target" >&2
    exit 1
  fi
  if [[ ! -f "$AUTO_SBOM_MANIFESTS_PATH" ]]; then
    echo "auto-SBOM manifest support file missing: $AUTO_SBOM_MANIFESTS_PATH" >&2
    exit 1
  fi

  find "$target" \
    \( -type d \( \
      -name .git -o \
      -name node_modules -o \
      -name vendor -o \
      -name __pycache__ -o \
      -name .build -o \
      -name .gotmp \
    \) -prune \) \
    -o -type f -print |
    while IFS= read -r file; do
      name="$(basename "$file")"
      dir="$(dirname "$file")"
      emit_auto_sbom_requirement_ids_for_manifest "$file" "$name" "$dir"
    done | sort -u
}

prepare_target_filter() {
  target_ids=""
  if [[ "$PROFILE" == "sbom" && -n "$TARGET" ]]; then
    target_ids="$(detect_sbom_ids "$TARGET")"
    if [[ -z "$target_ids" ]]; then
      echo "No auto-SBOM generator requirements detected under '$TARGET'."
      echo "Packmon can still scan native lockfiles and existing SBOMs without extra tools."
      exit 0
    fi
    target_id_count="$(printf '%s\n' "$target_ids" | sed '/^$/d' | wc -l | tr -d ' ')"
    echo "Detected $target_id_count auto-SBOM requirement group(s) under '$TARGET'."
  fi
}

target_contains_id() {
  local id="$1"
  [[ -z "$target_ids" ]] && return 0
  printf '%s\n' "$target_ids" | grep -Fxq "$id"
}

requirement_applies() {
  local id="$1"
  local profiles="$2"
  if [[ -z "${id:-}" || "$id" == \#* ]]; then
    return 1
  fi
  in_profile "$profiles" || return 1
  target_contains_id "$id" || return 1
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

requirement_satisfied() {
  local command="$1"
  local version="$2"
  local installer="$3"
  local resolved="$4"
  [[ -n "$resolved" ]] || return 1
  [[ "$version" == "any" ]] && return 0

  local version_text
  version_text="$(tool_version "$command" "$resolved" "$installer")"
  if [[ "$installer" != "manual" ]]; then
    version_eq "$version_text" "$version"
    return
  fi

  case "$command" in
    go|node|npm|python) version_ge "$version_text" "${version#>=}" ;;
    mvn) version_ge "$version_text" "${version#>=}" && maven_java_satisfied "$resolved" ;;
    *) return 0 ;;
  esac
}
