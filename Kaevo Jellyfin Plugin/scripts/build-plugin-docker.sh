#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
PROJECT_FILE="src/Kaevo.Plugin.KaevoForJellyfin/Kaevo.Plugin.KaevoForJellyfin.csproj"
OUTPUT_DIR="$PROJECT_ROOT/artifacts/build"
SDK_IMAGE="${DOTNET_SDK_IMAGE:-mcr.microsoft.com/dotnet/sdk:8.0}"
DOCKER_CACHE_ROOT="${KAEVO_DOCKER_CACHE_ROOT:-$PROJECT_ROOT/.docker-cache}"
mkdir -p "$DOCKER_CACHE_ROOT/dotnet-home" "$DOCKER_CACHE_ROOT/nuget-packages"

command -v docker >/dev/null 2>&1 || {
    echo "Docker is required and was not found in PATH." >&2
    exit 1
}

rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

docker run --rm \
    --volume "$PROJECT_ROOT:/workspace" \
    --workdir /workspace \
    --user "$(id -u):$(id -g)" \
    --volume "$DOCKER_CACHE_ROOT/dotnet-home:/cache/dotnet-home" \
    --volume "$DOCKER_CACHE_ROOT/nuget-packages:/cache/nuget-packages" \
    --env DOTNET_CLI_HOME=/cache/dotnet-home \
    --env NUGET_PACKAGES=/cache/nuget-packages \
    "$SDK_IMAGE" \
    dotnet publish "$PROJECT_FILE" \
        --configuration Release \
        --output /workspace/artifacts/build \
        --no-self-contained \
        -p:UseAppHost=false \
        -p:BaseOutputPath=/tmp/kaevo-build/bin/ \
        -p:BaseIntermediateOutputPath=/tmp/kaevo-build/obj/

test -f "$OUTPUT_DIR/Kaevo.Plugin.KaevoForJellyfin.dll"
echo "Built: $OUTPUT_DIR/Kaevo.Plugin.KaevoForJellyfin.dll"
