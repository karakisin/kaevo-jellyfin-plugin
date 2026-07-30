using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class ProfileJellyfinBindingStoreTests
{
    private const string OwnerUserId = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string MemberUserId = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    [Fact]
    public void ExactMemberBindingResolves()
    {
        Assert.True(KaevoProfileJellyfinBindingStore.TryBind(
            string.Empty,
            "member-profile",
            MemberUserId,
            out var bindingsJson));

        Assert.True(KaevoProfileJellyfinBindingStore.TryResolve(
            bindingsJson,
            null,
            null,
            "member-profile",
            out var resolved));
        Assert.Equal(MemberUserId, resolved);
    }

    [Fact]
    public void MissingMemberDoesNotFallBackToOwner()
    {
        Assert.False(KaevoProfileJellyfinBindingStore.TryResolve(
            null,
            "owner-profile",
            OwnerUserId,
            "member-profile",
            out _));
    }

    [Fact]
    public void LegacyFallbackIsRestrictedToExactPairedProfile()
    {
        Assert.True(KaevoProfileJellyfinBindingStore.TryResolve(
            null,
            "owner-profile",
            OwnerUserId,
            "owner-profile",
            out var resolved));
        Assert.Equal(OwnerUserId, resolved);
        Assert.False(KaevoProfileJellyfinBindingStore.TryResolve(
            null,
            "owner-profile",
            OwnerUserId,
            null,
            out _));
    }

    [Fact]
    public void DamagedAuthoritativeMapFailsClosed()
    {
        Assert.False(KaevoProfileJellyfinBindingStore.TryResolve(
            "{damaged",
            "owner-profile",
            OwnerUserId,
            "owner-profile",
            out _));
        Assert.False(KaevoProfileJellyfinBindingStore.TryBind(
            "{damaged",
            "member-profile",
            MemberUserId,
            out var bindingsJson));
        Assert.Equal("{damaged", bindingsJson);
    }

    [Fact]
    public void BindingNormalizesGuidAndPreservesOtherProfiles()
    {
        Assert.True(KaevoProfileJellyfinBindingStore.TryBind(
            string.Empty,
            "owner-profile",
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            out var bindingsJson));
        Assert.True(KaevoProfileJellyfinBindingStore.TryBind(
            bindingsJson,
            "member-profile",
            "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            out bindingsJson));

        Assert.True(KaevoProfileJellyfinBindingStore.TryResolve(
            bindingsJson,
            null,
            null,
            "owner-profile",
            out var owner));
        Assert.True(KaevoProfileJellyfinBindingStore.TryResolve(
            bindingsJson,
            null,
            null,
            "member-profile",
            out var member));
        Assert.Equal(OwnerUserId, owner);
        Assert.Equal(MemberUserId, member);
    }
}
