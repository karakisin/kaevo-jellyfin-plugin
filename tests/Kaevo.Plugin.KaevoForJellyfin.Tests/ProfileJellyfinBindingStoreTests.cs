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
        Assert.Equal(
            KaevoProfileJellyfinBindingWriteResult.BindingStoreInvalid,
            KaevoProfileJellyfinBindingStore.TryBindWithResult(
                "{damaged",
                "member-profile",
                MemberUserId,
                out _));
        Assert.Equal(
            "binding_store_invalid",
            KaevoProfileJellyfinBindingStore.ProfileBindingState("{damaged"));
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

    [Fact]
    public void OneJellyfinIdentityCannotBackTwoCloudProfiles()
    {
        Assert.True(KaevoProfileJellyfinBindingStore.TryBind(
            string.Empty,
            "first-profile",
            MemberUserId,
            out var bindingsJson));

        Assert.False(KaevoProfileJellyfinBindingStore.TryBind(
            bindingsJson,
            "second-profile",
            MemberUserId,
            out var unchanged));
        Assert.Equal(bindingsJson, unchanged);
        Assert.Equal(
            KaevoProfileJellyfinBindingWriteResult.JellyfinUserAlreadyBound,
            KaevoProfileJellyfinBindingStore.TryBindWithResult(
                bindingsJson,
                "second-profile",
                MemberUserId,
                out _));
        Assert.Equal(
            "jellyfin_user_already_bound",
            KaevoProfileJellyfinBindingStore.ResponseState(
                KaevoProfileJellyfinBindingWriteResult.JellyfinUserAlreadyBound));
    }

    [Fact]
    public void ExactUnbindIsIdempotentAndCannotRemoveAnotherIdentity()
    {
        Assert.True(KaevoProfileJellyfinBindingStore.TryBind(
            string.Empty,
            "member-profile",
            MemberUserId,
            out var bindingsJson));

        Assert.False(KaevoProfileJellyfinBindingStore.TryUnbind(
            bindingsJson,
            "member-profile",
            OwnerUserId,
            out var unchanged));
        Assert.Equal(bindingsJson, unchanged);

        Assert.True(KaevoProfileJellyfinBindingStore.TryUnbind(
            bindingsJson,
            "member-profile",
            MemberUserId,
            out var emptyBindings));
        Assert.True(KaevoProfileJellyfinBindingStore.TryUnbind(
            emptyBindings,
            "member-profile",
            MemberUserId,
            out var stillEmpty));
        Assert.Equal(emptyBindings, stillEmpty);
    }
}
