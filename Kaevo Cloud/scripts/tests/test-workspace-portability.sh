#!/usr/bin/env bash
set -euo pipefail

CLOUD_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
OLD_ROOT="/Users/jeffersonsumagang/Developer/StageDoorNative/Kaevo Cloud"
scripts=()
while IFS= read -r script; do scripts+=("$script"); done < <(find "$CLOUD_ROOT/scripts" -maxdepth 1 -type f -name '*.sh' | sort)

[[ "${#scripts[@]}" -eq 12 ]]
! rg -F "$OLD_ROOT" "${scripts[@]}"

unrelated="$(mktemp -d "${TMPDIR:-/tmp}/kaevo-portability.XXXXXX")"
trap 'find "$unrelated" -depth -delete' EXIT

for script in "${scripts[@]}"; do
  output="$(cd "$unrelated" && KAEVO_PATH_RESOLUTION_ONLY=1 bash "$script")"
  [[ "$output" == "$CLOUD_ROOT" ]]
  bash -n "$script"
done

space_root="$unrelated/Cloud Root With Spaces"
mkdir -p "$space_root/infra"
cp "$CLOUD_ROOT/infra/template.yaml" "$space_root/infra/template.yaml"
output="$(cd / && KAEVO_CLOUD_ROOT="$space_root" KAEVO_PATH_RESOLUTION_ONLY=1 bash "${scripts[0]}")"
[[ "$output" == "$space_root" ]]

if KAEVO_CLOUD_ROOT="$unrelated/missing" KAEVO_PATH_RESOLUTION_ONLY=1 bash "${scripts[0]}" >/dev/null 2>&1; then exit 1; fi
touch "$unrelated/not-a-directory"
if KAEVO_CLOUD_ROOT="$unrelated/not-a-directory" KAEVO_PATH_RESOLUTION_ONLY=1 bash "${scripts[0]}" >/dev/null 2>&1; then exit 1; fi

temp_root="$unrelated/Temporary Output With Spaces"
mkdir -p "$temp_root"
source "$CLOUD_ROOT/scripts/lib/kaevo-workspace.sh"
kaevo_init_cloud_root "$CLOUD_ROOT/scripts"
KAEVO_TEMP_ROOT="$temp_root"
kaevo_init_cloud_root "$CLOUD_ROOT/scripts"
[[ "$KAEVO_PROVIDER_TEST_OUTPUT_ROOT" == "$temp_root/provider-tests" ]]

if KAEVO_TEMP_ROOT=/ kaevo_init_cloud_root "$CLOUD_ROOT/scripts" >/dev/null 2>&1; then exit 1; fi
evidence_root="$unrelated/security-evidence"
mkdir -p "$evidence_root/attempted-output"
KAEVO_SECURITY_ROOT="$evidence_root"
KAEVO_TEMP_ROOT="$evidence_root/attempted-output"
if kaevo_init_cloud_root "$CLOUD_ROOT/scripts" >/dev/null 2>&1; then exit 1; fi
unset KAEVO_SECURITY_ROOT
foreign_repo="$unrelated/foreign-repo"
mkdir "$foreign_repo"
git -C "$foreign_repo" init -q
KAEVO_TEMP_ROOT="$foreign_repo"
if kaevo_init_cloud_root "$CLOUD_ROOT/scripts" >/dev/null 2>&1; then exit 1; fi

echo "12 Cloud script portability checks passed."
