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

    private static KaevoConnectorSecrets Secrets(string sabUrl) => new(
        "connector", "playback", "jellyfin", Providers: new Dictionary<string, KaevoLocalProviderSecret>
        {
            ["sabnzbd"] = new(sabUrl, "secret", true)
        });
}
