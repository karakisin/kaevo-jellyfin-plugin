using System.Text.Json;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class DownloadControlBindingTests
{
    [Fact]
    public void ExactQueueReadUsesTheSupportedPagedCollectionRoute()
    {
        Assert.Equal(
            "/api/v3/queue?page=1&pageSize=1000",
            KaevoCloudConnectorService.ExactArrQueueReadPath);
    }

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

    [Fact]
    public void ExactQueueRecordIsSelectedFromTheSupportedPagedCollectionShape()
    {
        using var document = JsonDocument.Parse("""
            {
              "page": 1,
              "pageSize": 1000,
              "totalRecords": 2,
              "records": [
                { "id": 41, "downloadId": "other-job" },
                { "id": 2071545594, "downloadId": "exact-job" }
              ]
            }
            """);

        var record = KaevoCloudConnectorService.FindExactArrQueueRecord(
            document.RootElement,
            2071545594);

        Assert.True(record.HasValue);
        Assert.Equal("exact-job", record.Value.GetProperty("downloadId").GetString());
    }

    [Fact]
    public void MissingExactQueueIdNeverFallsBackToAnotherRecord()
    {
        using var document = JsonDocument.Parse("""
            { "records": [{ "id": 41, "downloadId": "other-job" }] }
            """);

        Assert.Null(KaevoCloudConnectorService.FindExactArrQueueRecord(
            document.RootElement,
            2071545594));
    }

    [Theory]
    [InlineData(true, "pause")]
    [InlineData(false, "resume")]
    public void SabnzbdStateChangeTargetsOnlyTheExactQueueJob(bool paused, string command)
    {
        const string exactDownloadId = "e41c87db-d088-4470-a8fe-cdd56faf0e9c";

        var query = KaevoCloudConnectorService.BuildSabnzbdQueueStateQuery(
            exactDownloadId,
            paused);

        Assert.Equal("queue", query["mode"].GetString());
        Assert.Equal(command, query["name"].GetString());
        Assert.Equal(exactDownloadId, query["value"].GetString());
    }

    private static KaevoConnectorSecrets Secrets(string sabUrl) => new(
        "connector", "playback", "jellyfin", Providers: new Dictionary<string, KaevoLocalProviderSecret>
        {
            ["sabnzbd"] = new(sabUrl, "secret", true)
        });
}
