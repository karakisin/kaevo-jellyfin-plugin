using System.Text.Json;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class SeerrRequestAuthorityTests
{
    [Fact]
    public void BoundMemberUsesExactCloudDerivedSeerrUser()
    {
        var parameters = Parameters(new
        {
            requester_mode = "bound_user",
            requester_user_id = 14
        });

        Assert.Equal(
            14,
            KaevoCloudConnectorService.ResolveSeerrCreateRequesterUserId(parameters));
    }

    [Fact]
    public void CanonicalOwnerUsesAuthenticatedConnectorIdentityWithoutUserOverride()
    {
        var parameters = Parameters(new
        {
            requester_mode = "authenticated_connection_owner"
        });

        Assert.Null(
            KaevoCloudConnectorService.ResolveSeerrCreateRequesterUserId(parameters));
    }

    [Fact]
    public void OwnerModeRejectsAnyInjectedRequesterUser()
    {
        var parameters = Parameters(new
        {
            requester_mode = "authenticated_connection_owner",
            requester_user_id = 999
        });

        Assert.Throws<InvalidOperationException>(() =>
            KaevoCloudConnectorService.ResolveSeerrCreateRequesterUserId(parameters));
    }

    [Fact]
    public void LegacyBoundCommandRemainsCompatible()
    {
        var parameters = Parameters(new { requester_user_id = 14 });

        Assert.Equal(
            14,
            KaevoCloudConnectorService.ResolveSeerrCreateRequesterUserId(parameters));
    }

    private static IReadOnlyDictionary<string, JsonElement> Parameters(object value)
    {
        var element = JsonSerializer.SerializeToElement(value);
        return element.EnumerateObject().ToDictionary(
            property => property.Name,
            property => property.Value.Clone(),
            StringComparer.Ordinal);
    }
}
