using Kaevo.Plugin.KaevoForJellyfin.Configuration;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class TwoWayProfileDeletionPolicyTests
{
    [Fact]
    public void TwoWayProfileDeletionIsDefaultOff()
    {
        var configuration = new PluginConfiguration();

        Assert.False(KaevoTwoWayProfileDeletionPolicy.Allows(configuration));
        var error = Assert.Throws<InvalidOperationException>(() =>
            KaevoTwoWayProfileDeletionPolicy.Require(configuration));
        Assert.Equal(KaevoTwoWayProfileDeletionPolicy.DisabledState, error.Message);
    }

    [Fact]
    public void ServerAdministratorMustExplicitlyEnableTwoWayProfileDeletion()
    {
        var configuration = new PluginConfiguration
        {
            TwoWayProfileDeletionEnabled = true
        };

        Assert.True(KaevoTwoWayProfileDeletionPolicy.Allows(configuration));
        KaevoTwoWayProfileDeletionPolicy.Require(configuration);
    }

    [Theory]
    [InlineData(false, false, "disabled")]
    [InlineData(true, true, null)]
    public void SignedProviderStatusPublishesExactDeletionSetting(
        bool enabled,
        bool expectedOk,
        string? expectedReason)
    {
        var configuration = new PluginConfiguration
        {
            TwoWayProfileDeletionEnabled = enabled
        };
        var secrets = new KaevoConnectorSecrets(string.Empty, string.Empty, string.Empty);

        var status = KaevoCloudConnectorService.BuildProviderStatus(
            secrets,
            configuration,
            includeOptimizer: true)["profile_deletion"];

        Assert.Equal(expectedOk, status.Ok);
        Assert.True(status.Configured);
        Assert.Equal(expectedReason, status.Reason);
    }
}
