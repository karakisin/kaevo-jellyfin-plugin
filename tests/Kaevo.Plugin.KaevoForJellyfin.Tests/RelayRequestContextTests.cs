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
