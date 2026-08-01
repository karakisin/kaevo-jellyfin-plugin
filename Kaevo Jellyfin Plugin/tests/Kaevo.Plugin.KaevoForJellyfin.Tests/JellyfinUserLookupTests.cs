using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class JellyfinUserLookupTests
{
    private static readonly Guid ExpectedId =
        Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");

    [Fact]
    public void FindsExactRuntimeUserWithoutCallingGetUserById()
    {
        var manager = new RuntimeUserManager(
            Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
            ExpectedId);

        Assert.True(KaevoJellyfinUserLookup.Exists(manager, ExpectedId));
        Assert.Equal(0, manager.GetUserByIdCallCount);
    }

    [Fact]
    public void MissingRuntimeUserFailsClosed()
    {
        var manager = new RuntimeUserManager(
            Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"));

        Assert.False(KaevoJellyfinUserLookup.Exists(manager, ExpectedId));
        Assert.Equal(0, manager.GetUserByIdCallCount);
    }

    [Fact]
    public void MissingUsersContractFailsClosed()
    {
        Assert.False(KaevoJellyfinUserLookup.Exists(new object(), ExpectedId));
        Assert.False(KaevoJellyfinUserLookup.Exists(null, ExpectedId));
        Assert.False(KaevoJellyfinUserLookup.Exists(
            new RuntimeUserManager(ExpectedId),
            Guid.Empty));
    }

    [Fact]
    public void LegacyUsersIdsPropertyRemainsSupported()
    {
        Assert.True(KaevoJellyfinUserLookup.Exists(
            new LegacyUserManager(ExpectedId),
            ExpectedId));
    }

    private sealed class RuntimeUserManager
    {
        private readonly IReadOnlyList<Guid> _userIds;

        internal RuntimeUserManager(params Guid[] userIds)
        {
            _userIds = userIds;
        }

        public IEnumerable<Guid> GetUsersIds() => _userIds;

        public int GetUserByIdCallCount { get; private set; }

        // This intentionally has a different return contract than Jellyfin
        // 10.10. The compatibility lookup must never bind to or invoke it.
        public object? GetUserById(Guid id)
        {
            GetUserByIdCallCount++;
            return _userIds.Contains(id) ? new object() : null;
        }
    }

    private sealed class LegacyUserManager
    {
        internal LegacyUserManager(params Guid[] userIds)
        {
            UsersIds = userIds;
        }

        public IEnumerable<Guid> UsersIds { get; }
    }
}
