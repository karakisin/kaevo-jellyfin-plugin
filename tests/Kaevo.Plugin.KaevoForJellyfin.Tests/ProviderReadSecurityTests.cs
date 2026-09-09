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

    [Theory]
    [InlineData("lidarr", "/api/v1/artist")]
    [InlineData("readarr", "/api/v1/author")]
    [InlineData("prowlarr", "/api/v1/indexerstatus")]
    [InlineData("bazarr", "/api/system/status")]
    [InlineData("tdarr", "/api/v2/status")]
    public void RemovedProviderRoutesAreRejected(string provider, string path)
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

    [Fact]
    public void ArrCatalogBatchRequiresTheExactImmutableIdentityContract()
    {
        Assert.True(KaevoCloudConnectorService.IsAllowedProviderReadRequest(
            "radarr", "/api/v3/movie", Query("tmdbIds", "11,22")));
        Assert.True(KaevoCloudConnectorService.IsAllowedProviderReadRequest(
            "sonarr", "/api/v3/series", Query("tvdbIds", "33")));

        Assert.False(KaevoCloudConnectorService.IsAllowedProviderReadRequest(
            "radarr", "/api/v3/movie", Query("tmdbIds", "11,11")));
        Assert.False(KaevoCloudConnectorService.IsAllowedProviderReadRequest(
            "radarr", "/api/v3/movie", Query("tvdbIds", "11")));
        Assert.False(KaevoCloudConnectorService.IsAllowedProviderReadRequest(
            "sonarr", "/api/v3/series", Query("tvdbIds", "0")));
        Assert.False(KaevoCloudConnectorService.IsAllowedProviderReadRequest(
            "sonarr", "/api/v3/series", Query("tvdbIds", string.Join(',', Enumerable.Range(1, 33)))));
    }

    [Fact]
    public void ArrCatalogBatchFiltersOnlyExactImmutableIdsAndRetainsProviderDuplicates()
    {
        using var catalog = JsonDocument.Parse("""
            [
              {"id":1,"tmdbId":11,"title":"Allowed"},
              {"id":2,"tmdbId":22,"title":"Other"},
              {"id":3,"tmdbId":11,"title":"Ambiguous duplicate"},
              {"id":4,"title":"Missing identity"}
            ]
            """);

        var filtered = KaevoCloudConnectorService.FilterArrCatalog(
            catalog.RootElement,
            "tmdbId",
            new HashSet<int> { 11 });

        Assert.Equal(2, filtered.GetArrayLength());
        Assert.All(filtered.EnumerateArray(), item => Assert.Equal(11, item.GetProperty("tmdbId").GetInt32()));
    }

    private static IReadOnlyDictionary<string, JsonElement> Query(params string[] values)
    {
        return Enumerable.Range(0, values.Length / 2).ToDictionary(
            index => values[index * 2],
            index => JsonSerializer.SerializeToElement(values[index * 2 + 1]));
    }
}
