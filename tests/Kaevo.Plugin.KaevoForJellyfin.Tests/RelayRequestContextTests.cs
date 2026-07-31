using Kaevo.Plugin.KaevoForJellyfin.Services;
using System.Text.Json;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class RelayRequestContextTests
{
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
