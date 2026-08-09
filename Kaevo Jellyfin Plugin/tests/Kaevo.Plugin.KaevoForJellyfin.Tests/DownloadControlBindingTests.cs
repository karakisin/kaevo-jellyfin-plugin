using System.Text.Json;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class DownloadControlBindingTests
{
    [Fact]
    public void ExactArrClientResolvesOnlyTheConfiguredMatchingDownloader()
    {
        using var document = JsonDocument.Parse("""
            {
              "implementation": "SABnzbd",
              "fields": [
                { "name": "host", "value": "sab.internal" },
                { "name": "port", "value": 8080 }
              ]
            }
            """);

        Assert.Equal("sabnzbd", KaevoCloudConnectorService.ResolveExactArrDownloadProvider(
            document.RootElement,
            Secrets("http://sab.internal:8080")));
    }

    [Theory]
    [InlineData("http://sab.internal:8081")]
    [InlineData("http://other.internal:8080")]
    public void ExactArrClientRejectsMismatchedConfiguredDownloaderEndpoint(string providerUrl)
    {
        using var document = JsonDocument.Parse("""
            {
              "implementation": "SABnzbd",
              "fields": [
                { "name": "host", "value": "sab.internal" },
                { "name": "port", "value": 8080 }
              ]
            }
            """);

        Assert.Null(KaevoCloudConnectorService.ResolveExactArrDownloadProvider(
            document.RootElement,
            Secrets(providerUrl)));
    }

    [Fact]
    public void UnsupportedArrClientImplementationNeverSelectsAConfiguredDownloader()
    {
        using var document = JsonDocument.Parse("""
            {
              "implementation": "Transmission",
              "fields": [
                { "name": "host", "value": "sab.internal" },
                { "name": "port", "value": 8080 }
              ]
            }
            """);

        Assert.Null(KaevoCloudConnectorService.ResolveExactArrDownloadProvider(
            document.RootElement,
            Secrets("http://sab.internal:8080")));
    }

    [Fact]
    public void QueueProjectionAddsOnlyOneVerifiedImmutableDownloadClientId()
    {
        using var document = JsonDocument.Parse("""
            {
              "records": [
                { "id": 41, "movieId": 7, "downloadId": "exact-job-1", "downloadClient": "display-only" },
                { "id": 42, "movieId": 8, "downloadId": "ambiguous-job", "downloadClient": "display-only" },
                { "id": 43, "movieId": 9, "downloadId": "unverified-job", "downloadClient": "display-only" }
              ]
            }
            """);

        var enriched = KaevoCloudConnectorService.EnrichQueueWithVerifiedDownloadClientCandidates(
            document.RootElement,
            new Dictionary<string, int[]>(StringComparer.Ordinal)
            {
                ["exact-job-1"] = [17],
                ["ambiguous-job"] = [17, 18]
            });

        var records = enriched.GetProperty("records");
        Assert.Equal(17, records[0].GetProperty("downloadClientId").GetInt32());
        Assert.False(records[1].TryGetProperty("downloadClientId", out _));
        Assert.False(records[2].TryGetProperty("downloadClientId", out _));
    }

    [Fact]
    public void QueueProjectionNeverOverwritesAProviderSuppliedDownloadClientId()
    {
        using var document = JsonDocument.Parse("""
            { "records": [{ "id": 41, "downloadId": "exact-job-1", "downloadClientId": 9 }] }
            """);

        var enriched = KaevoCloudConnectorService.EnrichQueueWithVerifiedDownloadClientCandidates(
            document.RootElement,
            new Dictionary<string, int[]>(StringComparer.Ordinal) { ["exact-job-1"] = [17] });

        Assert.Equal(9, enriched.GetProperty("records")[0].GetProperty("downloadClientId").GetInt32());
    }

    private static KaevoConnectorSecrets Secrets(string sabUrl) => new(
        "connector", "playback", "jellyfin", Providers: new Dictionary<string, KaevoLocalProviderSecret>
        {
            ["sabnzbd"] = new(sabUrl, "secret", true)
        });
}
