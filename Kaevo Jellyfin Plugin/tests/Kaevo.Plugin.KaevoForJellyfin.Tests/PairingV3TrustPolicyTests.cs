using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class PairingV3TrustPolicyTests
{
    [Theory]
    [InlineData(null, null)]
    [InlineData("", "")]
    [InlineData("{\"stale\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}", "kaevo-cloud-dev")]
    public void ProductionMigratesMissingOrStaleSavedTrust(string? keys, string? issuer)
    {
        Assert.True(KaevoPairingV3TrustPolicy.TryResolve(
            keys,
            issuer,
            "production",
            out var resolvedKeys,
            out var resolvedIssuer,
            out var migrated));

        Assert.True(migrated);
        Assert.Equal(KaevoPairingV3TrustPolicy.ProductionVerificationKeysJson, resolvedKeys);
        Assert.Equal(KaevoPairingV3TrustPolicy.ProductionIssuer, resolvedIssuer);
    }

    [Fact]
    public void CanonicalProductionTrustDoesNotRewriteConfiguration()
    {
        Assert.True(KaevoPairingV3TrustPolicy.TryResolve(
            KaevoPairingV3TrustPolicy.ProductionVerificationKeysJson,
            KaevoPairingV3TrustPolicy.ProductionIssuer,
            "production",
            out var resolvedKeys,
            out var resolvedIssuer,
            out var migrated));

        Assert.False(migrated);
        Assert.Equal(KaevoPairingV3TrustPolicy.ProductionVerificationKeysJson, resolvedKeys);
        Assert.Equal(KaevoPairingV3TrustPolicy.ProductionIssuer, resolvedIssuer);
    }

    [Fact]
    public void DevelopmentMigratesProductionTrustToCanonicalDevelopmentTrust()
    {
        Assert.True(KaevoPairingV3TrustPolicy.TryResolve(
            KaevoPairingV3TrustPolicy.ProductionVerificationKeysJson,
            KaevoPairingV3TrustPolicy.ProductionIssuer,
            "development",
            out var resolvedKeys,
            out var resolvedIssuer,
            out var migrated));

        Assert.True(migrated);
        Assert.Equal(KaevoPairingV3TrustPolicy.DevelopmentVerificationKeysJson, resolvedKeys);
        Assert.Equal(KaevoPairingV3TrustPolicy.DevelopmentIssuer, resolvedIssuer);
    }

    [Theory]
    [InlineData("unexpected")]
    [InlineData("security-stage")]
    public void UnsupportedEnvironmentDoesNotInheritProductionTrust(string environment)
    {
        Assert.False(KaevoPairingV3TrustPolicy.TryResolve(
            string.Empty,
            string.Empty,
            environment,
            out var resolvedKeys,
            out var resolvedIssuer,
            out var migrated));

        Assert.False(migrated);
        Assert.Empty(resolvedKeys);
        Assert.Empty(resolvedIssuer);
    }

    [Fact]
    public void ExplicitDevelopmentTrustRemainsSupported()
    {
        Assert.True(KaevoPairingV3TrustPolicy.TryResolve(
            KaevoPairingV3TrustPolicy.DevelopmentVerificationKeysJson,
            KaevoPairingV3TrustPolicy.DevelopmentIssuer,
            "development",
            out var resolvedKeys,
            out var resolvedIssuer,
            out var migrated));

        Assert.False(migrated);
        Assert.Equal(KaevoPairingV3TrustPolicy.DevelopmentVerificationKeysJson, resolvedKeys);
        Assert.Equal(KaevoPairingV3TrustPolicy.DevelopmentIssuer, resolvedIssuer);
    }

    [Fact]
    public void UnpinnedServerPreservesCanonicalDevelopmentTrust()
    {
        Assert.True(KaevoPairingV3TrustPolicy.TryResolve(
            KaevoPairingV3TrustPolicy.DevelopmentVerificationKeysJson,
            KaevoPairingV3TrustPolicy.DevelopmentIssuer,
            null,
            out var resolvedKeys,
            out var resolvedIssuer,
            out var migrated));

        Assert.False(migrated);
        Assert.Equal(KaevoPairingV3TrustPolicy.DevelopmentVerificationKeysJson, resolvedKeys);
        Assert.Equal(KaevoPairingV3TrustPolicy.DevelopmentIssuer, resolvedIssuer);
    }

    [Theory]
    [InlineData("v3-dev-20260722-1", "kaevo-cloud-dev", null, "development")]
    [InlineData("v3-production-20260820-1", "kaevo-cloud-production", null, "production")]
    [InlineData("v3-dev-20260722-1", "kaevo-cloud-dev", "development", "development")]
    [InlineData("v3-production-20260820-1", "kaevo-cloud-production", "production", "production")]
    public void AuthorizationSelectsOnlyItsPinnedEnvironment(string kid, string issuer, string? pinnedEnvironment, string expectedEnvironment)
    {
        var token = Authorization(kid, issuer);

        Assert.True(KaevoPairingV3TrustPolicy.TryResolveForAuthorization(
            token,
            pinnedEnvironment,
            out var resolvedKeys,
            out var resolvedIssuer,
            out var resolvedEnvironment));

        Assert.Equal(expectedEnvironment, resolvedEnvironment);
        Assert.Equal(issuer, resolvedIssuer);
        Assert.Equal(
            expectedEnvironment == "production"
                ? KaevoPairingV3TrustPolicy.ProductionVerificationKeysJson
                : KaevoPairingV3TrustPolicy.DevelopmentVerificationKeysJson,
            resolvedKeys);
    }

    [Theory]
    [InlineData("v3-dev-20260722-1", "kaevo-cloud-production", null)]
    [InlineData("v3-production-20260820-1", "kaevo-cloud-dev", null)]
    [InlineData("unknown", "kaevo-cloud-dev", null)]
    [InlineData("v3-dev-20260722-1", "kaevo-cloud-dev", "production")]
    [InlineData("v3-production-20260820-1", "kaevo-cloud-production", "development")]
    public void AuthorizationCannotCrossIssuerOrExplicitEnvironment(string kid, string issuer, string? pinnedEnvironment)
    {
        Assert.False(KaevoPairingV3TrustPolicy.TryResolveForAuthorization(
            Authorization(kid, issuer),
            pinnedEnvironment,
            out _,
            out _,
            out _));
    }

    [Theory]
    [InlineData("")]
    [InlineData("not-a-jwt")]
    [InlineData("e30.e30.signature")]
    [InlineData("eyJhbGciOjF9.eyJpc3MiOjF9.signature")]
    public void MalformedAuthorizationFailsClosed(string authorization)
    {
        Assert.False(KaevoPairingV3TrustPolicy.TryResolveForAuthorization(
            authorization,
            null,
            out _,
            out _,
            out _));
    }

    private static string Authorization(string kid, string issuer)
    {
        var header = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(new
        {
            alg = "EdDSA",
            typ = "kaevo-pairing-authorization+jwt",
            kid
        });
        var payload = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(new { iss = issuer });
        return KaevoPairingV3Crypto.Base64Url(header) + "." + KaevoPairingV3Crypto.Base64Url(payload) + ".signature";
    }
}
