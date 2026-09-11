using System.Text.Json;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class ProfileMediaAccessPolicyTests
{
    private const string User = "0123456789abcdef0123456789abcdef";
    private static Dictionary<string, object> Policy() => new()
    {
        ["IsDisabled"] = false, ["EnableMediaPlayback"] = true,
        ["EnablePlaybackRemuxing"] = true, ["EnableAudioPlaybackTranscoding"] = true,
        ["EnableVideoPlaybackTranscoding"] = true,
        ["EnableAllFolders"] = false, ["EnabledFolders"] = new[] { "restricted-library" },
        ["MaxParentalRating"] = 6
    };

    [Fact]
    public void ExactReadOnlyVerificationPreservesRestrictions()
    {
        var user = JsonSerializer.SerializeToElement(new { Id = User, Policy = Policy() });
        var before = user.GetRawText();
        Assert.True(KaevoProfileMediaAccessPolicy.PlaybackReady(user, User));
        Assert.Equal(before, user.GetRawText());
        Assert.False(KaevoProfileMediaAccessPolicy.PlaybackReady(user, new string('b', 32)));
    }

    [Theory]
    [InlineData("IsDisabled", true)]
    [InlineData("EnableMediaPlayback", false)]
    [InlineData("EnablePlaybackRemuxing", false)]
    [InlineData("EnableAudioPlaybackTranscoding", false)]
    [InlineData("EnableVideoPlaybackTranscoding", false)]
    public void DisabledOrIncompletePlaybackIsNeverReportedReady(string key, bool value)
    {
        var policy = Policy(); policy[key] = value;
        Assert.False(KaevoProfileMediaAccessPolicy.PlaybackReady(JsonSerializer.SerializeToElement(new { Id = User, Policy = policy }), User));
        policy.Remove(key);
        Assert.False(KaevoProfileMediaAccessPolicy.PlaybackReady(JsonSerializer.SerializeToElement(new { Id = User, Policy = policy }), User));
        policy[key] = value.ToString();
        Assert.False(KaevoProfileMediaAccessPolicy.PlaybackReady(JsonSerializer.SerializeToElement(new { Id = User, Policy = policy }), User));
    }

    [Theory]
    [InlineData(42, 32, true, true)]
    [InlineData(42, 2, true, true)]
    [InlineData(43, 32, true, false)]
    [InlineData(42, 32, false, false)]
    [InlineData(42, 0, true, false)]
    public async Task SeerrVerificationOnlyReadsTheExactPair(int id, int permissions, bool sameUser, bool expected)
    {
        var calls = new List<string>();
        var service = new KaevoSeerrIdentityProvisioningService((_, method, path, body, _) =>
        {
            Assert.Equal(HttpMethod.Get, method); Assert.Null(body); calls.Add(path);
            return Task.FromResult(new KaevoSeerrIdentityProvisioningService.ProviderResponse(200,
                JsonSerializer.SerializeToElement(new { id, permissions, jellyfinUserId = sameUser ? User : new string('b', 32) })));
        });
        Assert.Equal(expected, await service.VerifyExactRequestAccessAsync(new KaevoConnectorSecrets("", "", "", "", ""), User, 42, CancellationToken.None));
        Assert.Equal(new[] { "/api/v1/user/42" }, calls);
    }
}
