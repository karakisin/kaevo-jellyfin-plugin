using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using Jellyfin.Data.Entities;
using MediaBrowser.Controller.Net;
using Kaevo.Plugin.KaevoForJellyfin.Api;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class KaevoControllerPairingIdentityTests
{
    private static readonly Guid UserId = Guid.Parse("123e4567-e89b-12d3-a456-426614174000");

    private static AuthorizationInfo Identity(bool authenticated = true, bool apiKey = false) => new()
    {
        IsAuthenticated = authenticated,
        IsApiKey = apiKey,
        User = new User("test", "test", "test") { Id = UserId }
    };

    [Fact] public void AcceptsExactlyTheAuthenticatedUser() =>
        Assert.True(KaevoController.IsPairingUserAuthenticated(Identity(), UserId.ToString("N")));

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, true)]
    [InlineData(false, true)]
    public void RejectsUnauthenticatedAndApiKeyIdentities(bool authenticated, bool apiKey) =>
        Assert.False(KaevoController.IsPairingUserAuthenticated(Identity(authenticated, apiKey), UserId.ToString("N")));

    [Fact] public void RejectsAnotherUser() =>
        Assert.False(KaevoController.IsPairingUserAuthenticated(Identity(), Guid.NewGuid().ToString("N")));

    [Fact] public void RejectsAbsentOrEmptyIdentity()
    {
        Assert.False(KaevoController.IsPairingUserAuthenticated(null, UserId.ToString("N")));
        Assert.False(KaevoController.IsPairingUserAuthenticated(new AuthorizationInfo { IsAuthenticated = true }, Guid.Empty.ToString("N")));
    }

    [Fact] public void CompiledPluginUsesStableUserIdWithoutReferencingMovedUserEntity()
    {
        using var stream = File.OpenRead(typeof(KaevoController).Assembly.Location);
        using var pe = new PEReader(stream);
        var metadata = pe.GetMetadataReader();
        var members = metadata.MemberReferences.Select(metadata.GetMemberReference)
            .Where(m => m.Parent.Kind == HandleKind.TypeReference)
            .Where(m => metadata.GetString(metadata.GetTypeReference((TypeReferenceHandle)m.Parent).Name) == "AuthorizationInfo")
            .Select(m => metadata.GetString(m.Name)).ToArray();
        Assert.Contains("get_UserId", members);
        Assert.DoesNotContain("get_User", members);
    }
}
