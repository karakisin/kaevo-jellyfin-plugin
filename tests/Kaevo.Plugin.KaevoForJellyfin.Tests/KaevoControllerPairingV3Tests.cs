using System.Text.Json;
using Kaevo.Plugin.KaevoForJellyfin.Api;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class KaevoControllerPairingV3Tests
{
    [Fact]
    public void CompleteRequestParserAcceptsTheExactV3Shape()
    {
        using var document = JsonDocument.Parse("""
            {"protocol":"kaevo-pairing-v3","ticketId":"ticket","pairingAttemptId":"123e4567-e89b-12d3-a456-426614174000","challengeId":"challenge","challengeNonce":"nonce","challengeResponseSignature":"signature","authorization":"synthetic.nonsecret.authorization","jellyfinUserId":"user","correlationId":"123e4567-e89b-12d3-a456-426614174001"}
            """);

        Assert.True(KaevoController.TryParsePairingV3Completion(document.RootElement, out var request));
        Assert.Equal("kaevo-pairing-v3", request.Protocol);
        Assert.Equal("ticket", request.TicketId);
        Assert.Equal("user", request.JellyfinUserId);
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("{\"protocol\":\"kaevo-pairing-v3\",\"ticketId\":17}")]
    [InlineData("[]")]
    public void CompleteRequestParserRejectsMissingOrNonStringFieldsWithoutExposingValues(string payload)
    {
        using var document = JsonDocument.Parse(payload);

        Assert.False(KaevoController.TryParsePairingV3Completion(document.RootElement, out _));
    }
}
