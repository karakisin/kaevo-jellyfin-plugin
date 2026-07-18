#!/usr/bin/env bash

kaevo_init_cloud_root() {
  local script_dir="$1"
  local derived_root

  derived_root="$(cd -- "$script_dir/.." >/dev/null 2>&1 && pwd -P)" || {
    echo "Kaevo Cloud root could not be derived from the script location." >&2
    return 64
  }

  ROOT="${KAEVO_CLOUD_ROOT:-$derived_root}"
  if [[ -z "$ROOT" || ! -d "$ROOT" || ! -f "$ROOT/infra/template.yaml" ]]; then
    echo "KAEVO_CLOUD_ROOT must identify a Kaevo Cloud repository directory: $ROOT" >&2
    return 64
  fi
  ROOT="$(cd -- "$ROOT" >/dev/null 2>&1 && pwd -P)" || return 64

  if [[ -n "${KAEVO_TEMP_ROOT:-}" ]]; then
    if [[ ! -d "$KAEVO_TEMP_ROOT" ]]; then
      echo "KAEVO_TEMP_ROOT must be an existing directory: $KAEVO_TEMP_ROOT" >&2
      return 64
    fi
    local resolved_temp git_root
    resolved_temp="$(cd -- "$KAEVO_TEMP_ROOT" >/dev/null 2>&1 && pwd -P)" || return 64
    case "$resolved_temp" in
      /|/System|/System/*|/Library|/Library/*)
        echo "KAEVO_TEMP_ROOT is not a safe output directory: $resolved_temp" >&2
        return 64
        ;;
    esac
    if [[ -n "${KAEVO_SECURITY_ROOT:-}" ]]; then
      local resolved_security
      resolved_security="$(cd -- "$KAEVO_SECURITY_ROOT" >/dev/null 2>&1 && pwd -P)" || return 64
      case "$resolved_temp/" in "$resolved_security/"*)
        echo "KAEVO_TEMP_ROOT must not be inside the security evidence tree." >&2
        return 64
      esac
    fi
    git_root="$(git -C "$resolved_temp" rev-parse --show-toplevel 2>/dev/null || true)"
    if [[ -n "$git_root" && "$git_root" != "$ROOT" ]]; then
      echo "KAEVO_TEMP_ROOT must not be inside an unrelated repository: $git_root" >&2
      return 64
    fi
    KAEVO_PROVIDER_TEST_OUTPUT_ROOT="$resolved_temp/provider-tests"
  else
    KAEVO_PROVIDER_TEST_OUTPUT_ROOT="$ROOT/docs/provider-tests"
  fi

  export KAEVO_CLOUD_ROOT="$ROOT"
  export KAEVO_PROVIDER_TEST_OUTPUT_ROOT

  if [[ "${KAEVO_PATH_RESOLUTION_ONLY:-0}" == "1" ]]; then
    printf '%s\n' "$ROOT"
    return 10
  fi
}
