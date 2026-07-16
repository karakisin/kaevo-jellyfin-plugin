using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class ProviderReadSecurityTests
{
    [Theory]
    [InlineData("seerr", "/api/v1/search")]
    [InlineData("sonarr", "/api/v3/series")]
    [InlineData("radarr", "/api/v3/movie")]
    [InlineData("lidarr", "/api/v1/artist")]
    [InlineData("readarr", "/api/v1/author")]
    [InlineData("prowlarr", "/api/v1/indexerstatus")]
    [InlineData("bazarr", "/api/system/status")]
    [InlineData("tdarr", "/api/v2/status")]
    public void AllowsBoundedReadOnlyProviderRoutes(string provider, string path)
    {
        Assert.True(KaevoCloudConnectorService.IsAllowedProviderReadPath(provider, path));
    }

    [Theory]
    [InlineData("seerr", "https://example.invalid/api/v1/search")]
    [InlineData("sonarr", "/api/v3/../admin")]
    [InlineData("sonarr", "/api/v3/command")]
    [InlineData("unknown", "/api/v1/status")]
    public void RejectsAbsoluteTraversalMutationAndUnknownRoutes(string provider, string path)
    {
        Assert.False(KaevoCloudConnectorService.IsAllowedProviderReadPath(provider, path));
    }
}
