using System.Net;
using System.Text;
using System.Text.Json;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class PairingV3CloudResponseTests
{
    private static readonly Uri Cloud = new("https://kaevo-development-mobile-9z2mf5rz.wl.gateway.dev");
    private const string User = "123e4567e89b12d3a456426614174000";
    private const string Profile = "prf1_123e4567-e89b-12d3-a456-426614174000";
    private static KaevoPairingV3RedemptionRequest Redeem => new("test", "ticket", "attempt", "plugin", "key", "fingerprint", "server", User, "jti", "kid", "1", "nonce", "signature", "correlation");
    private static KaevoPairingV3StatusRequest Status => new("attempt", "jti", "plugin", "key", "fingerprint", "server", "1", "nonce", "signature", "kid", "correlation");
    private static string Payload(string profile, string user = User, string connector = "v3_test", bool idempotent = false) => JsonSerializer.Serialize(new { protocol = "kaevo-pairing-v3", code = "pairing_redeemed", connectorId = connector, profileId = profile, jellyfinUserId = user, idempotent });

    [Theory]
    [InlineData(Profile)]
    [InlineData("profile_abcdefghijklmnop12345678")]
    [InlineData("legacy-profile:42")]
    public async Task AcceptsEachCanonicalProfileFormatInCreateAndRecovery(string profile)
    {
        foreach(var recovery in new[] {false,true})
        {
            using var http = new HttpClient(new Handler(Payload(profile, idempotent:recovery), recovery ? HttpStatusCode.OK : HttpStatusCode.Created));
            var client = new KaevoPairingV3CloudClient(http);
            var result = recovery ? await client.StatusAsync(Cloud, Status, default) : await client.RedeemAsync(Cloud, Redeem, default);
            Assert.Equal("pairing_redeemed", result.Code);
            Assert.Equal(profile, result.ProfileId);
            Assert.Equal(User, result.JellyfinUserId);
            Assert.Equal(recovery, result.Idempotent);
        }
    }

    [Theory]
    [InlineData("")]
    [InlineData("_invalid")]
    [InlineData("prf1_123e4567-e89b-12d3-a456-426614174000\n")]
    [InlineData("profile_abcdefghijklmnop\n")]
    [InlineData("profile/another")]
    [InlineData("profile with spaces")]
    public async Task RejectsMalformedProfileIds(string profile)
    {
        using var http = new HttpClient(new Handler(Payload(profile), HttpStatusCode.Created));
        Assert.Equal("ambiguous_enrollment", (await new KaevoPairingV3CloudClient(http).RedeemAsync(Cloud, Redeem, default)).Code);
    }

    [Theory]
    [InlineData(200,"", "v3_test")]
    [InlineData(201,User, "")]
    [InlineData(500,User, "v3_test")]
    [InlineData(302,User, "v3_test")]
    [InlineData(201,User+"\n", "v3_test")]
    public async Task RejectsIncompleteOrUnsuccessfulRedemption(int status, string user, string connector)
    {
        using var http = new HttpClient(new Handler(Payload(Profile,user,connector), (HttpStatusCode)status));
        Assert.Equal("ambiguous_enrollment", (await new KaevoPairingV3CloudClient(http).RedeemAsync(Cloud, Redeem, default)).Code);
    }

    [Fact] public async Task RejectsOverlongProfileId()
    {
        using var http = new HttpClient(new Handler(Payload(new string('a', 129)), HttpStatusCode.Created));
        Assert.Equal("ambiguous_enrollment", (await new KaevoPairingV3CloudClient(http).RedeemAsync(Cloud, Redeem, default)).Code);
    }

    private sealed class Handler(string body, HttpStatusCode status) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => Task.FromResult(new HttpResponseMessage(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") });
    }
}
