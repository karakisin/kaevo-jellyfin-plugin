using Kaevo.Plugin.KaevoForJellyfin.Services;
using MediaBrowser.Controller.Security;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class JellyfinApiKeyProvisionerTests
{
    [Fact]
    public async Task ExistingDedicatedKeyIsReusedWithoutCreatingAnother()
    {
        var authentication = new FakeAuthenticationManager(new AuthenticationInfo
        {
            AppName = KaevoJellyfinApiKeyProvisioner.ApiKeyName,
            AccessToken = "existing-token",
            DateCreated = new DateTime(2026, 8, 31, 0, 0, 0, DateTimeKind.Utc)
        });

        var token = await new KaevoJellyfinApiKeyProvisioner(authentication).EnsureAsync(default);

        Assert.Equal("existing-token", token);
        Assert.Equal(0, authentication.CreateCount);
    }

    [Fact]
    public async Task CleanPairingCreatesAndReturnsDedicatedKey()
    {
        var authentication = new FakeAuthenticationManager();

        var token = await new KaevoJellyfinApiKeyProvisioner(authentication).EnsureAsync(default);

        Assert.Equal("created-token-1", token);
        Assert.Equal(1, authentication.CreateCount);
        Assert.Equal(KaevoJellyfinApiKeyProvisioner.ApiKeyName, authentication.Keys.Single().AppName);
    }

    [Fact]
    public async Task MissingCreatedKeyFailsClosed()
    {
        var authentication = new FakeAuthenticationManager { PersistCreatedKey = false };

        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            () => new KaevoJellyfinApiKeyProvisioner(authentication).EnsureAsync(default));

        Assert.Equal("jellyfinApiKeyProvisioningFailed", error.Message);
    }

    private sealed class FakeAuthenticationManager : IAuthenticationManager
    {
        internal FakeAuthenticationManager(params AuthenticationInfo[] keys)
        {
            Keys.AddRange(keys);
        }

        internal List<AuthenticationInfo> Keys { get; } = [];
        internal int CreateCount { get; private set; }
        internal bool PersistCreatedKey { get; set; } = true;

        public Task CreateApiKey(string name)
        {
            CreateCount++;
            if (PersistCreatedKey)
            {
                Keys.Add(new AuthenticationInfo
                {
                    AppName = name,
                    AccessToken = $"created-token-{CreateCount}",
                    DateCreated = DateTime.UtcNow
                });
            }
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<AuthenticationInfo>> GetApiKeys()
            => Task.FromResult<IReadOnlyList<AuthenticationInfo>>(Keys);

        public Task DeleteApiKey(string accessToken)
        {
            Keys.RemoveAll(key => string.Equals(key.AccessToken, accessToken, StringComparison.Ordinal));
            return Task.CompletedTask;
        }
    }
}
