#!/usr/bin/env bash
# Build the isolated Household Join Lambda with Lambda-compatible Linux/arm64
# dependencies. It never updates CloudFormation or Lambda directly.
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly SOURCE_DIR="${ROOT_DIR}/api/src"
readonly LOCK_FILE="${ROOT_DIR}/api/requirements/household-join-linux-arm64.lock"
readonly IMAGE="public.ecr.aws/sam/build-python3.12@sha256:68466219d657d496aa275e5a4d72ca4763feb5de9ec83986c5f5d542a643805a"
readonly OUTPUT_DIR="${1:-${ROOT_DIR}/build/household-join-linux-arm64}"
readonly STAGING_DIR="$(mktemp -d "${TMPDIR:-/tmp}/kaevo-household-join.XXXXXX")"

cleanup() { rm -rf "${STAGING_DIR}"; }
trap cleanup EXIT

test -f "${LOCK_FILE}"
mkdir -p "${OUTPUT_DIR}"
rsync -a --delete \
  --exclude '__pycache__/' \
  --exclude '.pytest_cache/' \
  --exclude '*.pyc' \
  --exclude 'requirements.txt' \
  "${SOURCE_DIR}/" "${STAGING_DIR}/application/"
cp "${LOCK_FILE}" "${STAGING_DIR}/requirements.lock"

docker run --rm --platform linux/arm64 \
  --volume "${STAGING_DIR}:/work" \
  --workdir /work \
  --env KAEVO_BUILD_IMAGE="${IMAGE}" \
  "${IMAGE}" \
  /bin/sh -ec '
    python -m pip install --disable-pip-version-check --no-cache-dir --requirement requirements.lock --target package
    cp -a application/. package/
    find package -type d -name __pycache__ -prune -exec rm -rf {} +
    find package -type f -name "*.pyc" -delete
    find package -type d \( -name test -o -name tests \) -prune -exec rm -rf {} +
    PYTHONDONTWRITEBYTECODE=1 AWS_EC2_METADATA_DISABLED=true AWS_DEFAULT_REGION=us-west-2 PYTHONPATH=/work/package python - <<"PY"
import cryptography
import household_join_handler
print("cryptography", cryptography.__version__)
print("handler_import", household_join_handler.lambda_handler.__name__)
PY
    native="$(find package -type f \( -name "*.so" -o -name "*.dylib" \) -print)"
    test -n "${native}"
    for artifact in ${native}; do
      description="$(file -b "${artifact}")"
      printf "%s: %s\\n" "${artifact#package/}" "${description}"
      case "${description}" in
        *Mach-O*|*universal*|*x86-64*|*x86_64*) exit 41 ;;
        *ELF*ARM*aarch64*|*ELF*AArch64*) ;;
        *) exit 42 ;;
      esac
    done
    python - <<"PY"
import json
import os
import stat
import zipfile
from pathlib import Path

root = Path("package")
with zipfile.ZipFile("household-join-linux-arm64.zip", "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        entry = zipfile.ZipInfo(path.relative_to(root).as_posix(), (2024, 1, 1, 0, 0, 0))
        entry.compress_type = zipfile.ZIP_DEFLATED
        entry.external_attr = (stat.S_IMODE(path.stat().st_mode) & 0xFFFF) << 16
        archive.writestr(entry, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)

native = []
for path in sorted(p for p in root.rglob("*") if p.suffix in {".so", ".dylib"}):
    native.append(path.relative_to(root).as_posix())
Path("package-manifest.json").write_text(json.dumps({
    "runtime": "python3.12",
    "architecture": "linux/arm64",
    "build_image": os.environ["KAEVO_BUILD_IMAGE"],
    "file_count": sum(1 for p in root.rglob("*") if p.is_file()),
    "native_extensions": native,
}, sort_keys=True, indent=2) + "\n")
PY
  '

readonly SHA256="$(shasum -a 256 "${STAGING_DIR}/household-join-linux-arm64.zip" | awk '{print $1}')"
readonly ARTIFACT="${OUTPUT_DIR}/kaevo-household-join-linux-arm64-${SHA256}.zip"
cp "${STAGING_DIR}/household-join-linux-arm64.zip" "${ARTIFACT}"
cp "${STAGING_DIR}/package-manifest.json" "${OUTPUT_DIR}/kaevo-household-join-linux-arm64-${SHA256}.manifest.json"
printf 'artifact=%s\nsha256=%s\n' "${ARTIFACT}" "${SHA256}"
