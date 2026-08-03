using Kaevo.Plugin.KaevoForJellyfin.Services;
using System.Text.Json;
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
    [InlineData("sabnzbd", "/api")]
    [InlineData("qbittorrent", "/api/v2/app/version")]
    [InlineData("qbittorrent", "/api/v2/transfer/info")]
    [InlineData("qbittorrent", "/api/v2/torrents/info")]
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

    [Fact]
    public void AllowsOnlyTheNarrowDownloaderReadContracts()
    {
        Assert.True(KaevoCloudConnectorService.IsAllowedProviderReadRequest("sabnzbd", "/api", Query("mode", "queue")));
        Assert.True(KaevoCloudConnectorService.IsAllowedProviderReadRequest("qbittorrent", "/api/v2/torrents/info", null));

        Assert.False(KaevoCloudConnectorService.IsAllowedProviderReadRequest("sabnzbd", "/api", null));
        Assert.False(KaevoCloudConnectorService.IsAllowedProviderReadRequest("sabnzbd", "/api", Query("mode", "pause")));
        Assert.False(KaevoCloudConnectorService.IsAllowedProviderReadRequest("sabnzbd", "/api", Query("mode", "queue", "apikey", "not-accepted")));
        Assert.False(KaevoCloudConnectorService.IsAllowedProviderReadRequest("qbittorrent", "/api/v2/torrents/info", Query("filter", "all")));
    }

    private static IReadOnlyDictionary<string, JsonElement> Query(params string[] values)
    {
        return Enumerable.Range(0, values.Length / 2).ToDictionary(
            index => values[index * 2],
            index => JsonSerializer.SerializeToElement(values[index * 2 + 1]));
    }
}
