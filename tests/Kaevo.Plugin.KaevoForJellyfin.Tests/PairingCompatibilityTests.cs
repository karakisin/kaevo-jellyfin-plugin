using System.Text.Json;
using Kaevo.Plugin.KaevoForJellyfin.Configuration;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class PairingCompatibilityTests
{
    [Fact]
    public void FreshInstallationCannotAdvertiseUsablePairing()
    {
        var result = KaevoPairingCompatibility.ForConfiguration(new PluginConfiguration(), "0.3.test");
        Assert.Equal(new[] { 3 }, result.SupportedProtocols);
        Assert.Empty(result.EnabledProtocols);
        Assert.False(result.ConfigurationReady);
    }

    [Theory]
    [InlineData("", "{}")]
    [InlineData("issuer", "{}")]
    [InlineData("issuer", "bad json")]
    [InlineData("issuer", "{\"key\":\"a\"}")]
    public void MissingOrMalformedTrustConfigurationRemainsBlocked(string issuer, string keys)
    {
        var config = new PluginConfiguration { PairingV3Enabled = true,
            CloudBaseUrl = "https://o25nzxe9bk.execute-api.us-west-2.amazonaws.com/production",
            PairingV3CloudAuthorizationIssuer = issuer, PairingV3CloudAuthorizationVerificationKeysJson = keys };
        Assert.False(KaevoPairingCompatibility.ForConfiguration(config, "test").ConfigurationReady);
    }

    [Fact]
    public void CapabilityResponseIsRedactedAndReflectsConfiguredV3()
    {
        var config = new PluginConfiguration { PairingV3Enabled = true,
            CloudBaseUrl = "https://o25nzxe9bk.execute-api.us-west-2.amazonaws.com/production",
            PairingV3CloudAuthorizationIssuer = "private-issuer-binding",
            PairingV3CloudAuthorizationVerificationKeysJson = JsonSerializer.Serialize(new Dictionary<string, string>
                { ["verification-key"] = new string('A', 43) }) };
        var result = KaevoPairingCompatibility.ForConfiguration(config, "0.3.test");
        Assert.True(result.ConfigurationReady);
        Assert.Equal(new[] { 3 }, result.EnabledProtocols);
        var json = JsonSerializer.Serialize(result);
        Assert.DoesNotContain("private-issuer-binding", json);
        Assert.DoesNotContain("verification-key", json);
        config.CloudBaseUrl = "";
        Assert.False(KaevoPairingCompatibility.ForConfiguration(config, "test").ConfigurationReady);
        config.PairingV3Enabled = false;
        Assert.False(KaevoPairingCompatibility.ForConfiguration(config, "test").ConfigurationReady);
    }
}
