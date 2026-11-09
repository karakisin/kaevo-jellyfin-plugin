using Kaevo.Plugin.KaevoForJellyfin.Configuration;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class HeartbeatProviderRefreshTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
    private readonly KaevoSecretStore store;
    private readonly KaevoConnectorSecrets session = new("same-connector", "same-grant", "original-jellyfin");
    public HeartbeatProviderRefreshTests()
    {
        Directory.CreateDirectory(directory);
        store = new KaevoSecretStore(Path.Combine(directory, "secrets.json"), NullLogger<KaevoSecretStore>.Instance);
    }
    public void Dispose() => Directory.Delete(directory, true);

    [Theory]
    [InlineData("seerr")]
    [InlineData("radarr")]
    [InlineData("sonarr")]
    public async Task ExistingSessionAdvertisesSavedEnableDisableAndReenable(string provider)
    {
        foreach (var enabled in new[] { false, true, false, true })
        {
            await store.WriteAsync(session with { JellyfinApiKey = "new-jellyfin",
                Providers = new() { [provider] = new("http://127.0.0.1:1234", "provider-key", enabled) } }, default);
            var projected = await KaevoCloudConnectorService.ReadHeartbeatProviderSecretsAsync(store, session, default);
            var status = KaevoCloudConnectorService.BuildProviderStatus(projected, new PluginConfiguration(), false)[provider];
            Assert.True(status.Configured);
            Assert.Equal(enabled, status.Ok);
            Assert.Equal(enabled ? null : "disabled", status.Reason);
            Assert.Equal(session.ConnectorToken, projected.ConnectorToken);
            Assert.Equal(session.PlaybackGrantKey, projected.PlaybackGrantKey);
            Assert.Equal(session.JellyfinApiKey, projected.JellyfinApiKey);
        }
        await store.WriteAsync(session, default);
        var removed = await KaevoCloudConnectorService.ReadHeartbeatProviderSecretsAsync(store, session, default);
        Assert.False(KaevoCloudConnectorService.BuildProviderStatus(removed, new PluginConfiguration(), false)[provider].Configured);
    }

    [Theory]
    [InlineData("connector")]
    [InlineData("grant")]
    [InlineData("missing")]
    [InlineData("corrupt")]
    public async Task DifferentOrUnavailablePairingCannotAdvertiseProviderState(string change)
    {
        if (change == "corrupt") await File.WriteAllTextAsync(Path.Combine(directory, "secrets.json"), "invalid");
        else if (change != "missing") await store.WriteAsync(change == "connector"
            ? session with { ConnectorToken = "different" } : session with { PlaybackGrantKey = "different" }, default);
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            KaevoCloudConnectorService.ReadHeartbeatProviderSecretsAsync(store, session, default));
    }

    [Fact]
    public async Task LegacySonarrAndDownloaderSettingsRefreshWithoutChangingTransport()
    {
        await store.WriteAsync(session with { SonarrBaseUrl = "http://127.0.0.1:8989", SonarrApiKey = "legacy",
            Providers = new() { ["qbittorrent"] = new("http://127.0.0.1:8080", "", true) } }, default);
        var projected = await KaevoCloudConnectorService.ReadHeartbeatProviderSecretsAsync(store, session, default);
        var status = KaevoCloudConnectorService.BuildProviderStatus(projected, new PluginConfiguration(), false);
        Assert.True(status["sonarr"].Ok);
        Assert.True(status["downloaders"].Ok);
        await store.WriteAsync(session, default);
        projected = await KaevoCloudConnectorService.ReadHeartbeatProviderSecretsAsync(store, session, default);
        status = KaevoCloudConnectorService.BuildProviderStatus(projected, new PluginConfiguration(), false);
        Assert.False(status["sonarr"].Ok);
        Assert.False(status["downloaders"].Ok);
    }

    [Fact]
    public async Task CancellationDoesNotPublishStaleState()
    {
        await store.WriteAsync(session, default);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            KaevoCloudConnectorService.ReadHeartbeatProviderSecretsAsync(store, session, cancellation.Token));
    }
}
