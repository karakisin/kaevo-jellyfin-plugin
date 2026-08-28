using System.Text.Json;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class SeerrRequestAuthorityTests
{
    [Fact]
    public void BoundMemberUsesExactSeerrUserId()
    {
        var parameters = ParseParameters("""
            {
              "requester_mode": "bound_user",
              "requester_user_id": 42
            }
            """);

        Assert.Equal(42, KaevoCloudConnectorService.ResolveSeerrCreateRequesterUserId(parameters));
    }

    [Fact]
    public void CanonicalOwnerUsesAuthenticatedConnectorIdentity()
    {
        var parameters = ParseParameters("""
            {
              "requester_mode": "authenticated_connection_owner"
            }
            """);

        Assert.Null(KaevoCloudConnectorService.ResolveSeerrCreateRequesterUserId(parameters));
    }

    [Fact]
    public void CanonicalOwnerRejectsInjectedSeerrUserId()
    {
        var parameters = ParseParameters("""
            {
              "requester_mode": "authenticated_connection_owner",
              "requester_user_id": 42
            }
            """);

        var error = Assert.Throws<InvalidOperationException>(
            () => KaevoCloudConnectorService.ResolveSeerrCreateRequesterUserId(parameters));
        Assert.Equal("seerrRequesterModeInvalid", error.Message);
    }

    [Fact]
    public void LegacyCommandKeepsExactBoundUserCompatibility()
    {
        var parameters = ParseParameters("""
            {
              "requester_user_id": 17
            }
            """);

        Assert.Equal(17, KaevoCloudConnectorService.ResolveSeerrCreateRequesterUserId(parameters));
    }

    private static IReadOnlyDictionary<string, JsonElement> ParseParameters(string json)
    {
        using var document = JsonDocument.Parse(json);
        return document.RootElement.EnumerateObject()
            .ToDictionary(property => property.Name, property => property.Value.Clone(), StringComparer.Ordinal);
    }
}
