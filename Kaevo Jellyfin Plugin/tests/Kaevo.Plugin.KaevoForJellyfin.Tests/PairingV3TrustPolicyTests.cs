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

    [Theory]
    [InlineData("unexpected")]
    [InlineData("development")]
    [InlineData("security-stage")]
    public void NonProductionDoesNotInheritProductionTrust(string environment)
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
        const string keys = "{\"dev\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}";
        Assert.True(KaevoPairingV3TrustPolicy.TryResolve(
            keys,
            "kaevo-cloud-dev",
            "development",
            out var resolvedKeys,
            out var resolvedIssuer,
            out var migrated));

        Assert.False(migrated);
        Assert.Equal(keys, resolvedKeys);
        Assert.Equal("kaevo-cloud-dev", resolvedIssuer);
    }
}
