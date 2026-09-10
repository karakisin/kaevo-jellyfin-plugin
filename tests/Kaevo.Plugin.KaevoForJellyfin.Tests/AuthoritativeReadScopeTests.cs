using System.Text.Json;
using Kaevo.Plugin.KaevoForJellyfin.Configuration;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;
public sealed class AuthoritativeReadScopeTests
{
    private const string User = "11111111111111111111111111111111";
    private static CloudRequest Request(string method = "GET", string provider = "jellyfin", string connector = "connector-1", string user = User)
        => new("request-1", method, provider, "/kaevo/internal/main-snapshot", null, null, null,
            "profile_current", new("jellyfin", connector, user));

    [Fact]
    public void CurrentClaimCanReadWithoutReassigningStaleSavedOwnership()
    {
        var original = JsonSerializer.Serialize(new Dictionary<string,string> { ["profile_deleted"] = User });
        var saved = new PluginConfiguration { ConnectorId = "connector-1", ProfileJellyfinBindingsJson = original,
            RemoteMetadataEnabled = false, LocalJellyfinBaseUrl = "http://127.0.0.1:8096" };
        Assert.Throws<InvalidOperationException>(() => KaevoCloudConnectorService.AuthoritativeProfileProviderBindingUpdate(
            saved.ConnectorId, original, "", "", Request()));
        var scoped = KaevoCloudConnectorService.ConfigurationForAuthoritativeMediaRequest(saved, Request());
        Assert.NotSame(saved, scoped);
        Assert.Equal(original, saved.ProfileJellyfinBindingsJson);
        Assert.True(KaevoProfileJellyfinBindingStore.TryResolve(scoped, "profile_current", out var user));
        Assert.Equal(User, user);
        Assert.False(KaevoProfileJellyfinBindingStore.TryResolve(scoped, "profile_deleted", out _));
        Assert.False(scoped.RemoteMetadataEnabled);
        Assert.Equal(saved.LocalJellyfinBaseUrl, scoped.LocalJellyfinBaseUrl);
    }

    [Theory]
    [InlineData("COMMAND", "jellyfin", "connector-1", User)]
    [InlineData("GET", "seerr", "connector-1", User)]
    [InlineData("GET", "jellyfin", "other-connector", User)]
    [InlineData("GET", "jellyfin", "connector-1", "invalid")]
    public void RejectsWrongAuthorityScope(string method, string provider, string connector, string user)
    {
        var saved = new PluginConfiguration { ConnectorId = "connector-1" };
        Assert.Throws<InvalidOperationException>(() => KaevoCloudConnectorService.ConfigurationForAuthoritativeMediaRequest(saved, Request(method, provider, connector, user)));
        Assert.Equal("", saved.ProfileJellyfinBindingsJson);
    }

    [Fact]
    public void ConcurrentProfileReadsRemainIndependent()
    {
        var saved = new PluginConfiguration { ConnectorId = "connector-1" };
        var first = KaevoCloudConnectorService.ConfigurationForAuthoritativeMediaRequest(saved, Request());
        var second = KaevoCloudConnectorService.ConfigurationForAuthoritativeMediaRequest(saved, Request(user: "22222222222222222222222222222222") with { ProfileId = "profile_other" });
        Assert.True(KaevoProfileJellyfinBindingStore.TryResolve(first, "profile_current", out var firstUser));
        Assert.Equal(User, firstUser);
        Assert.False(KaevoProfileJellyfinBindingStore.TryResolve(second, "profile_current", out _));
        Assert.Equal("", saved.ProfileJellyfinBindingsJson);
    }
    [Theory]
    [InlineData("home_server")]
    [InlineData("jellyfin")]
    public void PlaybackPreparationUsesCurrentClaimWithoutOverwritingSavedOwner(string provider)
    {
        var original = JsonSerializer.Serialize(new Dictionary<string,string> { ["profile_deleted"] = User });
        var saved = new PluginConfiguration { ConnectorId = "connector-1", ProfileJellyfinBindingsJson = original };
        var request = Request(provider: provider) with { Method = "COMMAND", Operation = "jellyfin.prepare_playback", Path = "/commands/jellyfin.prepare_playback" };
        var scoped = KaevoCloudConnectorService.ConfigurationForAuthoritativeMediaRequest(saved, request);
        Assert.True(KaevoProfileJellyfinBindingStore.TryResolve(scoped, "profile_current", out var user));
        Assert.Equal(User, user);
        Assert.Equal(original, saved.ProfileJellyfinBindingsJson);
        Assert.Throws<InvalidOperationException>(() => KaevoCloudConnectorService.ConfigurationForAuthoritativeMediaRequest(saved, request with { ProfileProviderBinding = null }));
    }

    [Theory]
    [InlineData("jellyfin.mark_played", "/commands/jellyfin.mark_played")]
    [InlineData("jellyfin.delete_exact_bound_user", "/commands/jellyfin.delete_exact_bound_user")]
    [InlineData("jellyfin.prepare_playback", "/commands/jellyfin.delete_item")]
    public void OtherCommandsCannotBorrowPlaybackScope(string operation, string path)
    {
        var request = Request() with { Method = "COMMAND", Operation = operation, Path = path };
        Assert.False(KaevoCloudConnectorService.UsesAuthoritativeMediaScope(request));
        Assert.Throws<InvalidOperationException>(() => KaevoCloudConnectorService.ConfigurationForAuthoritativeMediaRequest(new() { ConnectorId = "connector-1" }, request));
    }
    [Theory]
    [InlineData("home_server", "GET", "/kaevo/internal/main-snapshot")]
    [InlineData("seerr", "COMMAND", "/commands/jellyfin.prepare_playback")]
    public void TransportProviderDoesNotBroadenUnrelatedRequests(string provider, string method, string path)
    {
        var request = Request(provider: provider) with { Method = method, Operation = "jellyfin.prepare_playback", Path = path };
        Assert.False(KaevoCloudConnectorService.UsesAuthoritativeMediaScope(request));
    }
    [Fact]
    public void SerializedHomeServerClaimSelectsCanonicalPlaybackUser()
    {
        var request = JsonSerializer.Deserialize<CloudRequest>("""
            {"request_id":"playback-1","profile_id":"profile_current","provider":"home_server",
             "method":"COMMAND","path":"/commands/jellyfin.prepare_playback",
             "operation":"jellyfin.prepare_playback","parameters":{"max_bitrate":40000000},
             "profile_provider_binding":{"provider":"jellyfin","connector_id":"connector-1",
                "provider_user_id":"11111111111111111111111111111111"}}
            """)!;
        var saved = new PluginConfiguration { ConnectorId = "connector-1",
            ProfileJellyfinBindingsJson = "{\"profile_deleted\":\"11111111111111111111111111111111\"}" };
        Assert.True(KaevoCloudConnectorService.UsesAuthoritativeMediaScope(request));
        var scoped = KaevoCloudConnectorService.ConfigurationForAuthoritativeMediaRequest(saved, request);
        Assert.True(KaevoProfileJellyfinBindingStore.TryResolve(scoped, request.ProfileId, out var user));
        Assert.Equal(User, user);
        Assert.Contains("profile_deleted", saved.ProfileJellyfinBindingsJson);
    }
}
