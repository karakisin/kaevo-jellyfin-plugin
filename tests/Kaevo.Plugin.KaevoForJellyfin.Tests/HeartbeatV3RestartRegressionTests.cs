using Kaevo.Plugin.KaevoForJellyfin.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class HeartbeatV3RestartRegressionTests
{
    [Theory]
    [InlineData("pairing")]
    [InlineData("connector")]
    [InlineData("grant")]
    [InlineData("jellyfin")]
    [InlineData("missing")]
    [InlineData("corrupt")]
    [InlineData("cancelled")]
    public async Task ChangedOrUnavailableAuthorityNeverRewritesSecrets(string scenario)
    {
        var directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "secrets.json");
        try
        {
            var store = new KaevoSecretStore(path, NullLogger<KaevoSecretStore>.Instance);
            var expected = new KaevoConnectorSecrets("legacy", "grant", "jellyfin");
            var current = scenario switch
            {
                "connector" => expected with { ConnectorToken = "changed" },
                "grant" => expected with { PlaybackGrantKey = "changed" },
                "jellyfin" => expected with { JellyfinApiKey = "changed" },
                _ => expected
            };
            if (scenario == "corrupt") await File.WriteAllTextAsync(path, "invalid");
            else if (scenario != "missing") await store.WriteAsync(current, default);
            var before = File.Exists(path) ? await File.ReadAllBytesAsync(path) : null;
            using var cancellation = new CancellationTokenSource();
            if (scenario == "cancelled") cancellation.Cancel();
            await Assert.ThrowsAnyAsync<Exception>(() => store.NormalizeVerifiedV3TransportAsync(expected,
                _ => Task.FromResult(scenario != "pairing"), cancellation.Token));
            Assert.Equal(before, File.Exists(path) ? await File.ReadAllBytesAsync(path) : null);
        }
        finally { Directory.Delete(directory, true); }
    }

    [Fact]
    public async Task NormalizationPreservesConcurrentProviderSettingsAndExistingJellyfinKey()
    {
        var directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var store = new KaevoSecretStore(Path.Combine(directory, "secrets.json"), NullLogger<KaevoSecretStore>.Instance);
            var expected = new KaevoConnectorSecrets("legacy", "grant", "explicit-jellyfin");
            var current = expected with { SonarrBaseUrl = "http://127.0.0.1:8989", SonarrApiKey = "sonarr",
                Providers = new() { ["seerr"] = new("http://127.0.0.1:5055", "new-provider", false) } };
            await store.WriteAsync(current, default);
            var normalized = await store.NormalizeVerifiedV3TransportAsync(expected, _ => Task.FromResult(true), default);
            Assert.Equal(current.JellyfinApiKey, normalized.JellyfinApiKey);
            Assert.Equal(current.SonarrBaseUrl, normalized.SonarrBaseUrl);
            Assert.Equal(current.SonarrApiKey, normalized.SonarrApiKey);
            Assert.Equal(current.Providers!["seerr"], normalized.Providers!["seerr"]);
        }
        finally { Directory.Delete(directory, true); }
    }

    [Fact]
    public async Task VerifiedV3RestartRetainsProviderProjectionAfterLegacySessionNormalization()
    {
        var directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var store = new KaevoSecretStore(Path.Combine(directory, "secrets.json"), NullLogger<KaevoSecretStore>.Instance);
            var saved = new KaevoConnectorSecrets("retired-connector-token", "retired-grant-key", "same-jellyfin",
                Providers: new() { ["seerr"] = new("http://127.0.0.1:5055", "same-provider", true) });
            await store.WriteAsync(saved, default);
            var session = await store.NormalizeVerifiedV3TransportAsync(saved, _ => Task.FromResult(true), default);
            var projection = await KaevoCloudConnectorService.ReadHeartbeatProviderSecretsAsync(store, session, default);
            Assert.Equal(saved.Providers!["seerr"], projection.Providers!["seerr"]);
            Assert.Equal("", projection.ConnectorToken);
            Assert.Equal("", projection.PlaybackGrantKey);
            Assert.Equal("same-jellyfin", projection.JellyfinApiKey);
            var persisted = await store.ReadAsync(default);
            Assert.Equal("", persisted!.ConnectorToken);
            var restarted = await store.NormalizeVerifiedV3TransportAsync(persisted, _ => Task.FromResult(true), default);
            await KaevoCloudConnectorService.ReadHeartbeatProviderSecretsAsync(store, restarted, default);
        }
        finally { Directory.Delete(directory, true); }
    }
}
