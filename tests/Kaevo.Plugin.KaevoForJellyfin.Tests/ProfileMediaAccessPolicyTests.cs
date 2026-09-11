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

    [Theory]
    [InlineData("owner", "owner", true, false, "authenticated_connection_owner", true)]
    [InlineData("member", "owner", true, false, "authenticated_connection_owner", false)]
    [InlineData("", "", true, false, "authenticated_connection_owner", false)]
    [InlineData("owner", "owner", false, false, "authenticated_connection_owner", false)]
    [InlineData("owner", "owner", true, true, "authenticated_connection_owner", false)]
    [InlineData("owner", "owner", true, false, "bound_user", false)]
    public void ConnectionOwnerRequiresExplicitModeAndExactConnectorOwner(
        string target, string owner, bool required, bool hasBoundUser, string mode, bool allowed)
    {
        var parameters = new Dictionary<string, JsonElement>
        {
            ["requests_required"] = JsonSerializer.SerializeToElement(required),
            ["requester_mode"] = JsonSerializer.SerializeToElement(mode)
        };
        if (hasBoundUser) parameters["seerr_user_id"] = JsonSerializer.SerializeToElement(42);
        if (allowed) Assert.True(KaevoProfileMediaAccessPolicy.UsesConnectionOwner(parameters, target, owner));
        else Assert.Throws<InvalidOperationException>(() => KaevoProfileMediaAccessPolicy.UsesConnectionOwner(parameters, target, owner));
        parameters.Remove("requester_mode");
        Assert.False(KaevoProfileMediaAccessPolicy.UsesConnectionOwner(parameters, target, owner));
    }

    [Theory]
    [InlineData(200, "{\"id\":1,\"permissions\":2}", true)]
    [InlineData(200, "{\"id\":7,\"permissions\":32}", true)]
    [InlineData(200, "{\"id\":1,\"permissions\":0}", false)]
    [InlineData(200, "{\"id\":1,\"permissions\":-1}", false)]
    [InlineData(200, "{\"id\":1,\"permissions\":8}", false)]
    [InlineData(200, "{\"id\":0,\"permissions\":2}", false)]
    [InlineData(200, "{\"id\":\"1\",\"permissions\":2}", false)]
    [InlineData(200, "{\"id\":1,\"permissions\":\"2\"}", false)]
    [InlineData(200, "{\"permissions\":2}", false)]
    [InlineData(200, "[]", false)]
    [InlineData(401, "{\"id\":1,\"permissions\":2}", false)]
    public async Task OwnerVerificationReadsOnlyTheCurrentlyAuthenticatedAccount(int status, string json, bool expected)
    {
        var calls = 0;
        var service = new KaevoSeerrIdentityProvisioningService((_, method, path, body, _) =>
        {
            calls++;
            Assert.Equal(HttpMethod.Get, method); Assert.Null(body); Assert.Equal("/api/v1/auth/me", path);
            return Task.FromResult(new KaevoSeerrIdentityProvisioningService.ProviderResponse(status,
                JsonDocument.Parse(json).RootElement.Clone()));
        });
        Assert.Equal(expected, await service.VerifyConnectionOwnerRequestAccessAsync(new KaevoConnectorSecrets("", "", "", "", ""), CancellationToken.None));
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task OwnerVerificationKeepsCancellationAndDoesNotRetryProviderFailure()
    {
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        var service = new KaevoSeerrIdentityProvisioningService((_, _, _, _, token) =>
            throw new OperationCanceledException(token));
        await Assert.ThrowsAsync<OperationCanceledException>(() => service.VerifyConnectionOwnerRequestAccessAsync(
            new KaevoConnectorSecrets("", "", "", "", ""), cancelled.Token));
        var count = 0;
        service = new KaevoSeerrIdentityProvisioningService((_, _, _, _, _) =>
        { count++; throw new HttpRequestException("offline"); });
        Assert.False(await service.VerifyConnectionOwnerRequestAccessAsync(new KaevoConnectorSecrets("", "", "", "", ""), CancellationToken.None));
        Assert.Equal(1, count);
    }
}
