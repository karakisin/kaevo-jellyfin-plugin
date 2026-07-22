#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
SDK_IMAGE="${DOTNET_SDK_IMAGE:-mcr.microsoft.com/dotnet/sdk:8.0}"
DOCKER_CACHE_ROOT="${KAEVO_DOCKER_CACHE_ROOT:-$PROJECT_ROOT/.docker-cache}"
mkdir -p "$DOCKER_CACHE_ROOT/dotnet-home" "$DOCKER_CACHE_ROOT/nuget-packages"

docker run --rm \
    --volume "$PROJECT_ROOT:/workspace" \
    --workdir /workspace \
    --user "$(id -u):$(id -g)" \
    --volume "$DOCKER_CACHE_ROOT/dotnet-home:/cache/dotnet-home" \
    --volume "$DOCKER_CACHE_ROOT/nuget-packages:/cache/nuget-packages" \
    --env DOTNET_CLI_HOME=/cache/dotnet-home \
    --env NUGET_PACKAGES=/cache/nuget-packages \
    "$SDK_IMAGE" \
    dotnet test tests/Kaevo.Plugin.KaevoForJellyfin.Tests/Kaevo.Plugin.KaevoForJellyfin.Tests.csproj \
        --configuration Release \
        --results-directory /tmp/kaevo-test-results
