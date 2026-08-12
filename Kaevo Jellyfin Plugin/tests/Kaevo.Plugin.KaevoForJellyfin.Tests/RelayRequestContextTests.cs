using Kaevo.Plugin.KaevoForJellyfin.Configuration;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using MediaBrowser.Model.Session;
using System.Text.Json;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class RelayRequestContextTests
{
    [Fact]
    public void RecoveryCommandReturnsOnlyExactProfileBinding()
    {
        const string profileId = "profile-member-1";
        const string userId = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        var request = new CloudRequest(
            "request-1", "COMMAND", "home_server", "/commands/jellyfin.recover_profile_binding",
            null, "jellyfin.recover_profile_binding", null, profileId);

        var recovered = KaevoCloudConnectorService.RecoverExactProfileJellyfinUserId(
            "{\"profile-member-1\":\"" + userId + "\"}",
            null,
            null,
            request);

        Assert.Equal(userId, recovered);
    }

    [Fact]
    public void RecoveryCommandNeverFallsBackToOwnerForMember()
    {
        var request = new CloudRequest(
            "request-1", "COMMAND", "home_server", "/commands/jellyfin.recover_profile_binding",
            null, "jellyfin.recover_profile_binding", null, "profile-member-1");

        var error = Assert.Throws<InvalidOperationException>(() =>
            KaevoCloudConnectorService.RecoverExactProfileJellyfinUserId(
                string.Empty,
                "profile-owner-1",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                request));

        Assert.Equal("profileJellyfinBindingMissing", error.Message);
    }

    [Fact]
    public void RecoveryCommandFailsClosedForCorruptAuthoritativeMap()
    {
        var request = new CloudRequest(
            "request-1", "COMMAND", "home_server", "/commands/jellyfin.recover_profile_binding",
            null, "jellyfin.recover_profile_binding", null, "profile-member-1");

        var error = Assert.Throws<InvalidOperationException>(() =>
            KaevoCloudConnectorService.RecoverExactProfileJellyfinUserId(
                "not-json",
                "profile-member-1",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                request));

        Assert.Equal("profileJellyfinBindingMissing", error.Message);
    }

    [Fact]
    public void CloudRequestDeserializesAuthoritativeProfileIdentity()
    {
        const string profileId = "profile-member-1";
        var request = JsonSerializer.Deserialize<CloudRequest>(
            $$"""{"request_id":"request-1","method":"GET","provider":"jellyfin","path":"/kaevo/internal/main-snapshot","profile_id":"{{profileId}}"}""",
            new JsonSerializerOptions(JsonSerializerDefaults.Web));

        Assert.NotNull(request);
        Assert.Equal(profileId, request.ProfileId);
    }

    [Fact]
    public void MainSnapshotContinueWatchingUsesCanonicalBoundUserResumeRoute()
    {
        const string userId = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        var request = KaevoCloudConnectorService.BuildMainSnapshotItemsRequest(
            userId,
            "Movie,Episode",
            20,
            true);

        Assert.Equal("/UserItems/Resume", request.Path);
        Assert.Equal(userId, request.Query["userId"].GetString());
        Assert.Equal(0, request.Query["startIndex"].GetInt32());
        Assert.Equal(20, request.Query["limit"].GetInt32());
        Assert.Equal("Video", request.Query["mediaTypes"].GetString());
        Assert.True(request.Query["enableUserData"].GetBoolean());
        Assert.True(request.Query["excludeActiveSessions"].GetBoolean());
        Assert.DoesNotContain("IsResumable", request.Query.Keys);
    }

    [Fact]
    public void MainSnapshotCatalogStillUsesExactUserItemsRoute()
    {
        const string userId = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        var request = KaevoCloudConnectorService.BuildMainSnapshotItemsRequest(
            userId,
            "Movie",
            80,
            null);

        Assert.Equal($"/Users/{userId}/Items", request.Path);
        Assert.Equal("Movie", request.Query["IncludeItemTypes"].GetString());
        Assert.False(request.Query.ContainsKey("userId"));
        Assert.False(request.Query.ContainsKey("IsResumable"));
    }

    [Fact]
    public void PlaybackProgressUsesExactProfileBindingAndOwnedSessionIdentity()
    {
        const string profileId = "profile-member-1";
        const string userId = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        var configuration = new PluginConfiguration
        {
            ProfileJellyfinBindingsJson = "{\"profile-member-1\":\"" + userId + "\"}"
        };
        var request = new CloudRequest(
            "request-1", "COMMAND", "home_server", "/commands/jellyfin.playback_progress",
            null, "jellyfin.playback_progress", null, profileId);
        var parameters = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(
            "{\"item_id\":\"11111111111111111111111111111111\",\"media_source_id\":\"media-1\",\"play_session_id\":\"session-1\",\"position_ticks\":21469465561,\"is_paused\":true}")!;

        var playback = KaevoCloudConnectorService.BuildBoundPlaybackRequest(
            configuration,
            request,
            "jellyfin.playback_progress",
            parameters);
        var info = Assert.IsType<PlaybackProgressInfo>(
            KaevoCloudConnectorService.BuildPlaybackInfo(
                playback,
                "jellyfin-session-1",
                PlayMethod.DirectPlay));

        Assert.Equal(userId, playback.JellyfinUserId);
        Assert.Equal(64, playback.DeviceId.Length);
        Assert.Equal(Guid.ParseExact("11111111111111111111111111111111", "N"), info.ItemId);
        Assert.Equal(21_469_465_561, info.PositionTicks);
        Assert.True(info.IsPaused);
        Assert.True(info.CanSeek);
        Assert.Equal(PlayMethod.DirectPlay, info.PlayMethod);
        Assert.Equal("jellyfin-session-1", info.SessionId);
    }

    [Fact]
    public void PlaybackSessionIdentityCannotCollideAcrossBoundUsers()
    {
        const string ownerUserId = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        const string memberUserId = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        var configuration = new PluginConfiguration
        {
            ProfileJellyfinBindingsJson = "{\"profile-owner-1\":\"" + ownerUserId
                + "\",\"profile-member-1\":\"" + memberUserId + "\"}"
        };
        var parameters = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(
            "{\"item_id\":\"11111111111111111111111111111111\",\"media_source_id\":\"media-1\",\"play_session_id\":\"shared-session\",\"position_ticks\":10000000}")!;
        var owner = KaevoCloudConnectorService.BuildBoundPlaybackRequest(
            configuration,
            new CloudRequest("request-1", "COMMAND", "home_server", "/commands/jellyfin.playback_started", null, "jellyfin.playback_started", null, "profile-owner-1"),
            "jellyfin.playback_started",
            parameters);
        var member = KaevoCloudConnectorService.BuildBoundPlaybackRequest(
            configuration,
            new CloudRequest("request-2", "COMMAND", "home_server", "/commands/jellyfin.playback_started", null, "jellyfin.playback_started", null, "profile-member-1"),
            "jellyfin.playback_started",
            parameters);

        Assert.NotEqual(owner.DeviceId, member.DeviceId);
    }

    [Fact]
    public void PlaybackNeverFallsBackToConnectorOwnerBinding()
    {
        var configuration = new PluginConfiguration
        {
            ProfileId = "profile-owner-1",
            JellyfinUserId = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ProfileJellyfinBindingsJson = "{\"profile-owner-1\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}"
        };
        var request = new CloudRequest(
            "request-1", "COMMAND", "home_server", "/commands/jellyfin.playback_stopped",
            null, "jellyfin.playback_stopped", null, "profile-member-1");
        var parameters = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(
            "{\"item_id\":\"11111111111111111111111111111111\",\"media_source_id\":\"media-1\",\"play_session_id\":\"session-1\",\"position_ticks\":10000000}")!;

        var error = Assert.Throws<InvalidOperationException>(() =>
            KaevoCloudConnectorService.BuildBoundPlaybackRequest(
                configuration,
                request,
                "jellyfin.playback_stopped",
                parameters));

        Assert.Equal("profileJellyfinBindingMissing", error.Message);
    }

    [Fact]
    public void ClaimedRequestDeserializesAndPersistsExactProviderBinding()
    {
        const string profileId = "profile-member-1";
        const string userId = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        var request = JsonSerializer.Deserialize<CloudRequest>(
            "{\"request_id\":\"request-1\",\"method\":\"GET\",\"provider\":\"jellyfin\",\"path\":\"/kaevo/internal/main-snapshot\",\"profile_id\":\""
                + profileId
                + "\",\"profile_provider_binding\":{\"provider\":\"jellyfin\",\"connector_id\":\"connector-1\",\"provider_user_id\":\""
                + userId
                + "\"}}",
            new JsonSerializerOptions(JsonSerializerDefaults.Web));
        Assert.NotNull(request);
        var update = KaevoCloudConnectorService.AuthoritativeProfileProviderBindingUpdate(
            "connector-1", string.Empty, null, null, request);

        Assert.True(KaevoProfileJellyfinBindingStore.TryResolve(
            update.BindingsJson, null, null, profileId, out var resolved));
        Assert.Equal(userId, resolved);
        Assert.True(update.Changed);
    }

    [Fact]
    public void ProviderBindingForAnotherConnectorFailsClosed()
    {
        var request = new CloudRequest(
            "request-1", "GET", "jellyfin", "/kaevo/internal/main-snapshot",
            null, null, null, "profile-member-1",
            new CloudProfileProviderBinding(
                "jellyfin", "connector-2", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"));

        var error = Assert.Throws<InvalidOperationException>(() =>
            KaevoCloudConnectorService.AuthoritativeProfileProviderBindingUpdate(
                "connector-1", string.Empty, null, null, request));

        Assert.Equal("profileProviderBindingInvalid", error.Message);
    }

    [Fact]
    public void ProviderBindingCannotSilentlyReplaceDifferentExistingIdentity()
    {
        Assert.True(KaevoProfileJellyfinBindingStore.TryBind(
            string.Empty,
            "profile-member-1",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            out var bindingsJson));
        var request = new CloudRequest(
            "request-1", "GET", "jellyfin", "/kaevo/internal/main-snapshot",
            null, null, null, "profile-member-1",
            new CloudProfileProviderBinding(
                "jellyfin", "connector-1", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"));

        var error = Assert.Throws<InvalidOperationException>(() =>
            KaevoCloudConnectorService.AuthoritativeProfileProviderBindingUpdate(
                "connector-1", bindingsJson, null, null, request));

        Assert.Equal("profileJellyfinBindingConflict", error.Message);
        Assert.True(KaevoProfileJellyfinBindingStore.TryResolve(
            bindingsJson, null, null, "profile-member-1", out var retained));
        Assert.Equal("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", retained);
    }

    [Fact]
    public void BodyAcknowledgementControlMessageDeserializesWithRequestBinding()
    {
        const string requestId = "12345678-1234-1234-1234-123456789012";
        var message = JsonSerializer.Deserialize<RelayMessage>(
            $$"""{"type":"body_ack","request_id":"{{requestId}}"}""",
            new JsonSerializerOptions(JsonSerializerDefaults.Web));

        Assert.NotNull(message);
        Assert.Equal("body_ack", message.Type);
        Assert.Equal(requestId, message.RequestId);
    }

    [Fact]
    public void LateRelayMessagesAfterRequestCleanupAreIgnored()
    {
        var context = new KaevoCloudConnectorService.RelayRequestContext(CancellationToken.None);
        context.Dispose();

        context.AcknowledgeBody();
        context.Cancel();
    }

    [Fact]
    public async Task DuplicateBodyAcknowledgementKeepsSingleChunkWindow()
    {
        using var context = new KaevoCloudConnectorService.RelayRequestContext(CancellationToken.None);

        context.AcknowledgeBody();
        context.AcknowledgeBody();

        Assert.True(await context.WaitForBodyAcknowledgementAsync(TimeSpan.FromMilliseconds(100)));
        Assert.False(await context.WaitForBodyAcknowledgementAsync(TimeSpan.FromMilliseconds(20)));
    }
}
