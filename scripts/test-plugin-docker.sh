#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
SDK_IMAGE="${DOTNET_SDK_IMAGE:-mcr.microsoft.com/dotnet/sdk:8.0}"

docker run --rm \
    --volume "$PROJECT_ROOT:/workspace" \
    --workdir /workspace \
    --user "$(id -u):$(id -g)" \
    --env DOTNET_CLI_HOME=/tmp/dotnet-home \
    --env NUGET_PACKAGES=/tmp/nuget-packages \
    "$SDK_IMAGE" \
    dotnet test tests/Kaevo.Plugin.KaevoForJellyfin.Tests/Kaevo.Plugin.KaevoForJellyfin.Tests.csproj \
        --configuration Release \
        --results-directory /tmp/kaevo-test-results
