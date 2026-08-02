using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class OwnerAuthorizedUnboundClaimTests
{
    private const string Target = "profile_target";
    private const string Owner = "profile_owner";
    private const string Other = "profile_other";
    private const string User = "0123456789abcdef0123456789abcdef";
    private const string OtherUser = "fedcba9876543210fedcba9876543210";
    private const string Operation = "operation_claim_abcdefghijklmnop";

    [Fact]
    public void UnboundInspectionAndClaimAreGuardedAndIdempotent()
    {
        var bindings = string.Empty;
        var claimOperations = string.Empty;
        var inspection = KaevoProfileJellyfinBindingStore.InspectUnboundClaim(
            bindings, Target, User, out var source, out var revision);

        Assert.Equal(KaevoProfileJellyfinBindingUnboundClaimInspectionResult.Eligible, inspection);
        Assert.Empty(source);
        Assert.Equal(KaevoProfileJellyfinBindingUnboundClaimResult.Claimed,
            KaevoProfileJellyfinBindingStore.TryClaimUnboundUser(bindings, claimOperations, revision, Target, User, Operation, out bindings, out claimOperations));
        Assert.Equal(KaevoProfileJellyfinBindingUnboundClaimResult.AlreadyBound,
            KaevoProfileJellyfinBindingStore.TryClaimUnboundUser(bindings, claimOperations, revision, Target, User, Operation, out _, out _));
        Assert.Contains("sha256:", claimOperations, StringComparison.Ordinal);
    }

    [Fact]
    public void RevisionChangeBlocksClaimWithoutWriting()
    {
        var bindings = $"{{\"{Owner}\":\"{OtherUser}\"}}";
        _ = KaevoProfileJellyfinBindingStore.InspectUnboundClaim(
            bindings, Target, User, out _, out var revision);
        bindings = $"{{\"{Owner}\":\"{OtherUser}\",\"{Other}\":\"11111111111111111111111111111111\"}}";

        Assert.Equal(KaevoProfileJellyfinBindingUnboundClaimResult.BindingRevisionMismatch,
            KaevoProfileJellyfinBindingStore.TryClaimUnboundUser(bindings, string.Empty, revision, Target, User, Operation, out var updatedBindings, out _));
        Assert.Equal(bindings, updatedBindings);
    }

    [Theory]
    [InlineData("owner")]
    [InlineData("other")]
    public void ExistingOwnerBlocksNewClaim(string source)
    {
        var existing = source == "owner" ? Owner : Other;
        var bindings = $"{{\"{existing}\":\"{User}\"}}";
        _ = KaevoProfileJellyfinBindingStore.InspectUnboundClaim(
            bindings, Target, User, out _, out var revision);

        Assert.Equal(KaevoProfileJellyfinBindingUnboundClaimResult.OwnerConflict,
            KaevoProfileJellyfinBindingStore.TryClaimUnboundUser(bindings, string.Empty, revision, Target, User, Operation, out var updatedBindings, out _));
        Assert.Equal(bindings, updatedBindings);
    }

    [Fact]
    public void TargetConflictAndAmbiguousMapNeverRewriteExistingBindings()
    {
        var targetConflict = $"{{\"{Target}\":\"{OtherUser}\"}}";
        _ = KaevoProfileJellyfinBindingStore.InspectUnboundClaim(targetConflict, Target, User, out _, out var targetRevision);
        Assert.Equal(KaevoProfileJellyfinBindingUnboundClaimResult.TargetAlreadyBound,
            KaevoProfileJellyfinBindingStore.TryClaimUnboundUser(targetConflict, string.Empty, targetRevision, Target, User, Operation, out _, out _));

        var ambiguous = $"{{\"{Owner}\":\"{User}\",\"{Other}\":\"{User}\"}}";
        _ = KaevoProfileJellyfinBindingStore.InspectUnboundClaim(ambiguous, Target, User, out _, out var ambiguousRevision);
        Assert.Equal(KaevoProfileJellyfinBindingUnboundClaimResult.OwnerAmbiguous,
            KaevoProfileJellyfinBindingStore.TryClaimUnboundUser(ambiguous, string.Empty, ambiguousRevision, Target, User, Operation, out _, out _));
    }

    [Fact]
    public void ExistingProfileTransferMovesOnlyTheInspectedOwnerWithRevisionCas()
    {
        var bindings = $"{{\"{Owner}\":\"{User}\",\"{Other}\":\"{OtherUser}\"}}";
        _ = KaevoProfileJellyfinBindingStore.InspectUnboundClaim(
            bindings, Target, User, out var source, out var revision);
        Assert.Equal(Owner, source);

        Assert.Equal(
            KaevoProfileJellyfinBindingExistingTransferResult.Transferred,
            KaevoProfileJellyfinBindingStore.TryTransferExistingUser(
                bindings, revision, Owner, Target, User, out var transferred));
        Assert.True(KaevoProfileJellyfinBindingStore.TryResolve(transferred, null, null, Target, out var targetUser));
        Assert.Equal(User, targetUser);
        Assert.False(KaevoProfileJellyfinBindingStore.TryResolve(transferred, null, null, Owner, out _));
        Assert.True(KaevoProfileJellyfinBindingStore.TryResolve(transferred, null, null, Other, out var otherUser));
        Assert.Equal(OtherUser, otherUser);

        Assert.Equal(
            KaevoProfileJellyfinBindingExistingTransferResult.AlreadyTransferred,
            KaevoProfileJellyfinBindingStore.TryTransferExistingUser(
                transferred, revision, Owner, Target, User, out var retried));
        Assert.Equal(transferred, retried);
    }

    [Fact]
    public void ExistingProfileTransferRefusesDriftAndNeverRewritesBindings()
    {
        var bindings = $"{{\"{Owner}\":\"{User}\",\"{Other}\":\"{OtherUser}\"}}";
        _ = KaevoProfileJellyfinBindingStore.InspectUnboundClaim(
            bindings, Target, User, out _, out var revision);
        var drifted = $"{{\"{Owner}\":\"{User}\",\"{Other}\":\"{OtherUser}\",\"profile_new\":\"11111111111111111111111111111111\"}}";

        Assert.Equal(
            KaevoProfileJellyfinBindingExistingTransferResult.BindingRevisionMismatch,
            KaevoProfileJellyfinBindingStore.TryTransferExistingUser(
                drifted, revision, Owner, Target, User, out var revisionUnchanged));
        Assert.Equal(drifted, revisionUnchanged);

        Assert.Equal(
            KaevoProfileJellyfinBindingExistingTransferResult.SourceChanged,
            KaevoProfileJellyfinBindingStore.TryTransferExistingUser(
                bindings, revision, Other, Target, User, out var sourceUnchanged));
        Assert.Equal(bindings, sourceUnchanged);

        var occupied = $"{{\"{Owner}\":\"{User}\",\"{Target}\":\"{OtherUser}\"}}";
        Assert.Equal(
            KaevoProfileJellyfinBindingExistingTransferResult.TargetAlreadyBound,
            KaevoProfileJellyfinBindingStore.TryTransferExistingUser(
                occupied, KaevoProfileJellyfinBindingStore.MemberBindingRevision("unused", User), Owner, Target, User, out var targetUnchanged));
        Assert.Equal(occupied, targetUnchanged);
    }
}
