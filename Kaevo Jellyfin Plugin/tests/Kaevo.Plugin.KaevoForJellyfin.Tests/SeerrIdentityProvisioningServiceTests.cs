using System.Text.Json;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class SeerrIdentityProvisioningServiceTests
{
    private const string JellyfinUserId = "0123456789abcdef0123456789abcdef";

    [Fact]
    public async Task ImportsExactJellyfinUserAndAppliesOnlyRequestPermissions()
    {
        var calls = new List<(string Method, string Path, string Body)>();
        var reads = 0;
        var service = new KaevoSeerrIdentityProvisioningService((_, method, path, body, _) =>
        {
            calls.Add((method.Method, path, JsonSerializer.Serialize(body)));
            if (method == HttpMethod.Get && path == "/api/v1/user")
            {
                reads++;
                return Task.FromResult(Response(reads == 1
                    ? "{\"results\":[]}"
                    : $"{{\"results\":[{{\"id\":42,\"jellyfinUserId\":\"{JellyfinUserId}\",\"permissions\":26}}]}}"));
            }
            if (method == HttpMethod.Post)
            {
                return Task.FromResult(Response($"[{{\"id\":42,\"jellyfinUserId\":\"{JellyfinUserId}\",\"permissions\":26}}]"));
            }
            if (method == HttpMethod.Get && path == "/api/v1/user/42")
            {
                var permissions = calls.Any(call => call.Method == "PUT") ? 32 : 26;
                return Task.FromResult(Response($"{{\"id\":42,\"jellyfinUserId\":\"{JellyfinUserId}\",\"permissions\":{permissions}}}"));
            }
            return Task.FromResult(Response($"{{\"id\":42,\"jellyfinUserId\":\"{JellyfinUserId}\",\"permissions\":32}}"));
        });

        var result = await service.EnsureJellyfinUserAccessAsync(
            Secrets(), JellyfinUserId, 32, CancellationToken.None);

        Assert.Equal("ready", result.State);
        Assert.Equal(42, result.SeerrUserId);
        Assert.Contains(calls, call => call.Method == "POST"
            && call.Path == "/api/v1/user/import-from-jellyfin"
            && call.Body.Contains(JellyfinUserId, StringComparison.Ordinal));
        Assert.Contains(calls, call => call.Method == "PUT"
            && call.Path == "/api/v1/user/42"
            && call.Body.Contains("32", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(2)]
    [InlineData(8)]
    [InlineData(16)]
    public void RejectsManagementAndInvalidPermissionBits(int permissions)
    {
        Assert.False(KaevoSeerrIdentityProvisioningService.IsSafeRequestPermissionMask(permissions));
    }

    [Fact]
    public void ParsesNestedExactJellyfinIdentity()
    {
        using var document = JsonDocument.Parse(
            $"{{\"id\":7,\"permissions\":32,\"jellyfinUser\":{{\"id\":\"{JellyfinUserId}\"}}}}");

        var user = KaevoSeerrIdentityProvisioningService.ParseSingleUser(document.RootElement);

        Assert.NotNull(user);
        Assert.Equal(JellyfinUserId, user!.JellyfinUserId);
    }

    [Fact]
    public async Task RefusesToDowngradeAnExistingPrivilegedSeerrIdentity()
    {
        var methods = new List<string>();
        var service = new KaevoSeerrIdentityProvisioningService((_, method, path, _, _) =>
        {
            methods.Add(method.Method);
            var json = path == "/api/v1/user"
                ? $"{{\"results\":[{{\"id\":7,\"jellyfinUserId\":\"{JellyfinUserId}\",\"permissions\":2}}]}}"
                : $"{{\"id\":7,\"jellyfinUserId\":\"{JellyfinUserId}\",\"permissions\":2}}";
            return Task.FromResult(Response(json));
        });

        var result = await service.EnsureJellyfinUserAccessAsync(
            Secrets(), JellyfinUserId, 32, CancellationToken.None);

        Assert.Equal("seerr_user_privileged", result.State);
        Assert.DoesNotContain("PUT", methods);
        Assert.DoesNotContain("DELETE", methods);
    }

    [Fact]
    public async Task DeletesOnlyTheExactBoundSeerrAndJellyfinIdentity()
    {
        var deleted = false;
        var service = new KaevoSeerrIdentityProvisioningService((_, method, path, _, _) =>
        {
            if (method == HttpMethod.Delete && path == "/api/v1/user/42")
            {
                deleted = true;
                return Task.FromResult(Response("{}"));
            }
            var users = deleted
                ? "{\"results\":[]}"
                : $"{{\"results\":[{{\"id\":42,\"jellyfinUserId\":\"{JellyfinUserId}\",\"permissions\":32}}]}}";
            return Task.FromResult(Response(users));
        });

        var result = await service.DeleteExactJellyfinUserAsync(
            Secrets(), JellyfinUserId, 42, CancellationToken.None);

        Assert.Equal("deleted", result.State);
        Assert.True(deleted);
    }

    [Fact]
    public async Task RefusesDeletionWhenTheExactJellyfinBindingDoesNotMatch()
    {
        var deleted = false;
        var service = new KaevoSeerrIdentityProvisioningService((_, method, _, _, _) =>
        {
            deleted |= method == HttpMethod.Delete;
            return Task.FromResult(Response(
                "{\"results\":[{\"id\":42,\"jellyfinUserId\":\"abcdefabcdefabcdefabcdefabcdefab\",\"permissions\":32}]}"));
        });

        var result = await service.DeleteExactJellyfinUserAsync(
            Secrets(), JellyfinUserId, 42, CancellationToken.None);

        Assert.Equal("seerr_identity_mismatch", result.State);
        Assert.False(deleted);
    }

    [Fact]
    public async Task RetryTreatsOnlyAuthoritativeDualIdentifierAbsenceAsSuccess()
    {
        var service = new KaevoSeerrIdentityProvisioningService((_, method, _, _, _) =>
        {
            Assert.NotEqual(HttpMethod.Delete, method);
            return Task.FromResult(Response("{\"results\":[]}"));
        });

        var result = await service.DeleteExactJellyfinUserAsync(
            Secrets(), JellyfinUserId, 42, CancellationToken.None);

        Assert.Equal("absent", result.State);
    }

    private static KaevoConnectorSecrets Secrets() => new(
        "connector", "playback", "jellyfin", Providers: new Dictionary<string, KaevoLocalProviderSecret>
        {
            ["seerr"] = new("http://seerr.test", "secret", true)
        });

    private static KaevoSeerrIdentityProvisioningService.ProviderResponse Response(string json)
    {
        using var document = JsonDocument.Parse(json);
        return new(200, document.RootElement.Clone());
    }
}
