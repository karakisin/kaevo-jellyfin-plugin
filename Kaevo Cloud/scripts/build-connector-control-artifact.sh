#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: build-connector-control-artifact.sh OUTPUT_ZIP" >&2
  exit 2
fi

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cloud_dir=$(cd "${script_dir}/.." && pwd)
output_zip=$1
artifact_dir=$(mktemp -d "${TMPDIR:-/tmp}/kaevo-control-artifact.XXXXXX")
cleanup() {
  rm -rf "${artifact_dir}"
}
trap cleanup EXIT

cp -R "${cloud_dir}/api/websocket_control" "${artifact_dir}/websocket_control"
cp -R "${cloud_dir}/api/connector_control" "${artifact_dir}/connector_control"
cp "${cloud_dir}/api/src/pairing_v3.py" "${artifact_dir}/pairing_v3.py"

python3 -m pip install \
  --requirement "${cloud_dir}/api/connector_control/requirements.txt" \
  --target "${artifact_dir}" \
  --platform manylinux_2_34_aarch64 \
  --platform manylinux2014_aarch64 \
  --implementation cp \
  --python-version 3.12 \
  --only-binary=:all: \
  --quiet

python3 "${cloud_dir}/api/connector_control/verify_linux_arm64_artifact.py" "${artifact_dir}"
find "${artifact_dir}" -type d -name __pycache__ -prune -exec rm -rf {} +
mkdir -p "$(dirname "${output_zip}")"
(cd "${artifact_dir}" && zip -X -q -r "${output_zip}" .)
shasum -a 256 "${output_zip}"
