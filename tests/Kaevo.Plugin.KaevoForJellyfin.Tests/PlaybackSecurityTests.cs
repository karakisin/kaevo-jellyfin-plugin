using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class PlaybackSecurityTests
{
    private const string ConnectorId = "connector-1";
    private const string GrantKey = "0123456789abcdef0123456789abcdef";
    private const string ItemId = "0123456789abcdef0123456789abcdef";

    [Fact]
    public void ValidGrantBindsConnectorAndPlaybackIdentifiers()
    {
        var grant = KaevoPlaybackSecurity.VerifyGrant(Token(), GrantKey, ConnectorId);

        Assert.Equal(ItemId, grant.ItemId);
        Assert.Equal("source-1", grant.MediaSourceId);
        Assert.Equal("session-1", grant.PlaybackSessionId);
    }

    [Fact]
    public void GrantFromAnotherConnectorIsRejected()
    {
        Assert.Throws<InvalidOperationException>(() =>
            KaevoPlaybackSecurity.VerifyGrant(Token(), GrantKey, "connector-2"));
    }

    [Fact]
    public void DirectPlayAllowsOnlyStreamAndBindsQuery()
    {
        var grant = KaevoPlaybackSecurity.VerifyGrant(Token(), GrantKey, ConnectorId);
        var request = KaevoPlaybackSecurity.Resolve(
            grant,
            "GET",
            $"/Videos/{ItemId}/stream",
            new Dictionary<string, JsonElement>(),
            "bytes=0-1023");

        Assert.Contains("mediaSourceId=source-1", request.PathAndQuery, StringComparison.Ordinal);
        Assert.Contains("playSessionId=session-1", request.PathAndQuery, StringComparison.Ordinal);
        Assert.Equal("bytes=0-1023", request.RangeHeader);
    }

    [Fact]
    public void DirectPlayRejectsHlsAndUnknownQuery()
    {
        var grant = KaevoPlaybackSecurity.VerifyGrant(Token(), GrantKey, ConnectorId);
        Assert.Throws<InvalidOperationException>(() => KaevoPlaybackSecurity.Resolve(
            grant, "GET", $"/Videos/{ItemId}/master.m3u8", null, null));
        Assert.Throws<InvalidOperationException>(() => KaevoPlaybackSecurity.Resolve(
            grant,
            "GET",
            $"/Videos/{ItemId}/stream",
            new Dictionary<string, JsonElement> { ["api_key"] = JsonSerializer.SerializeToElement("secret") },
            null));
    }

    [Fact]
    public void BitrateAboveGrantIsRejected()
    {
        var grant = KaevoPlaybackSecurity.VerifyGrant(Token(maxBitrate: 1_000_000), GrantKey, ConnectorId);
        Assert.Throws<InvalidOperationException>(() => KaevoPlaybackSecurity.Resolve(
            grant,
            "GET",
            $"/Videos/{ItemId}/stream",
            new Dictionary<string, JsonElement> { ["videoBitRate"] = JsonSerializer.SerializeToElement("2000000") },
            null));
    }

    private static string Token(int maxBitrate = 40_000_000)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var payload = new SortedDictionary<string, object>(StringComparer.Ordinal)
        {
            ["connector_id"] = ConnectorId,
            ["device_id"] = "ios-device-1",
            ["exp"] = now + 120,
            ["grant_id"] = "grant-1",
            ["iat"] = now,
            ["item_id"] = ItemId,
            ["max_bitrate"] = maxBitrate,
            ["max_concurrent"] = 1,
            ["media_source_id"] = "source-1",
            ["mode"] = "direct_play",
            ["nbf"] = now - 5,
            ["nonce"] = "nonce-abcdefghijklmnopqrstuvwx",
            ["playback_session_id"] = "session-1",
            ["profile_id"] = "profile-1",
            ["v"] = 1
        };
        var canonical = JsonSerializer.Serialize(payload);
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(GrantKey));
        var signature = Base64Url(hmac.ComputeHash(Encoding.UTF8.GetBytes(canonical)));
        payload["home_sig"] = signature;
        var encoded = Base64Url(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload)));
        return encoded + ".outer-signature-not-validated-by-home";
    }

    private static string Base64Url(byte[] value)
        => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
