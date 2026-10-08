using Kaevo.Plugin.KaevoForJellyfin.Configuration;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;
namespace Kaevo.Plugin.KaevoForJellyfin.Tests;
public sealed class NativePairingConfigurationTests
{
    [Fact] public void FreshConfigurationReceivesTrustButNeverConnectedState()
    {
        var config = new PluginConfiguration();
        Assert.True(KaevoNativePairingConfiguration.ApplyToUnconfigured(config));
        Assert.True(config.PairingV3Enabled);
        Assert.False(config.CloudConnectorEnabled);
        Assert.Empty(config.ConnectorId);
        Assert.Empty(config.ProfileJellyfinBindingsJson);
        Assert.True(KaevoPairingCompatibility.ForConfiguration(config, "0.3.79").ConfigurationReady);
        Assert.False(KaevoNativePairingConfiguration.ApplyToUnconfigured(config));
    }
    [Theory]
    [InlineData("connector")]
    [InlineData("profile")]
    [InlineData("endpoint")]
    [InlineData("trust")]
    [InlineData("enabled")]
    [InlineData("binding")]
    public void ExistingOrPausedConfigurationIsPreserved(string field)
    {
        var config = new PluginConfiguration();
        switch(field){
            case "connector":config.ConnectorId="retained";break;
            case "profile":config.ProfileId="retained";break;
            case "endpoint":config.CloudBaseUrl="https://existing.example";break;
            case "trust":config.PairingV3CloudAuthorizationIssuer="existing";break;
            case "enabled":config.CloudConnectorEnabled=true;break;
            case "binding":config.ProfileJellyfinBindingsJson="{}";break;
        }
        var before=System.Text.Json.JsonSerializer.Serialize(config);
        Assert.False(KaevoNativePairingConfiguration.ApplyToUnconfigured(config));
        Assert.Equal(before,System.Text.Json.JsonSerializer.Serialize(config));
    }
    [Theory]
    [InlineData("http://kaevo-development-mobile-9z2mf5rz.wl.gateway.dev")]
    [InlineData("https://kaevo-development-mobile-9z2mf5rz.wl.gateway.dev.evil.example")]
    [InlineData("https://kaevo-development-mobile-9z2mf5rz.wl.gateway.dev/path")]
    public void NativePairingScopeRequiresPinnedOrigin(string origin) => Assert.False(KaevoNativePairingConfiguration.IsNative(new Uri(origin)));
}
