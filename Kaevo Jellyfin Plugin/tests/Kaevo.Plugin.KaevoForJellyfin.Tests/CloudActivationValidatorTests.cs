using Kaevo.Plugin.KaevoForJellyfin.Models;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

[CollectionDefinition("Cloud environment", DisableParallelization = true)]
public sealed class CloudEnvironmentCollection;

[Collection("Cloud environment")]
public sealed class CloudActivationValidatorTests
{
    private static readonly KaevoCloudActivationRequest ValidRequest = new(
        "https://o25nzxe9bk.execute-api.us-west-2.amazonaws.com/production",
        "profile_stub",
        "123e4567-e89b-42d3-a456-426614174000",
        "ABCD-1234-EF56",
        "bf37113a073e40e8a22cd100cb3b8ac2",
        "0123456789abcdef0123456789abcdef");

    [Fact]
    public void OfficialCloudActivationIsAccepted()
    {
        var activation = KaevoCloudActivationValidator.Validate(ValidRequest);

        Assert.Equal("https://o25nzxe9bk.execute-api.us-west-2.amazonaws.com/production", activation.CloudBaseUrl);
        Assert.Equal("ABCD-1234-EF56", activation.PairingCode);
    }

    [Theory]
    [InlineData("http://aneohx5ff6.execute-api.us-west-2.amazonaws.com/dev")]
    [InlineData("https://aneohx5ff6.execute-api.us-west-2.amazonaws.com/dev")]
    [InlineData("https://o25nzxe9bk.execute-api.us-west-2.amazonaws.com/dev")]
    [InlineData("https://o25nzxe9bk.execute-api.us-west-2.amazonaws.com/production/extra")]
    [InlineData("https://api.kaevo.watch")]
    [InlineData("https://127.0.0.1/dev")]
    [InlineData("https://example.com/dev")]
    [InlineData("https://kaevo.app.evil.example/dev")]
    public void UnapprovedCloudDestinationsAreRejected(string cloudBaseUrl)
    {
        Assert.Throws<ArgumentException>(() =>
            KaevoCloudActivationValidator.Validate(ValidRequest with { CloudBaseUrl = cloudBaseUrl }));
    }

    [Fact]
    public void SecurityStageApiIsEnvironmentScoped()
    {
        const string host = "vsuh8a8v8i.execute-api.us-west-2.amazonaws.com";

        Assert.True(KaevoCloudEndpointPolicy.IsApprovedHost(host, "security-stage"));
        Assert.False(KaevoCloudEndpointPolicy.IsApprovedHost(host, "production"));
        Assert.False(KaevoCloudEndpointPolicy.IsApprovedHost("attacker.execute-api.us-west-2.amazonaws.com", "security-stage"));
    }

    [Theory]
    [InlineData("development", "https://aneohx5ff6.execute-api.us-west-2.amazonaws.com/dev")]
    [InlineData("dev", "https://api.kaevo.watch")]
    [InlineData("internal-qa", "https://aneohx5ff6.execute-api.us-west-2.amazonaws.com/dev")]
    [InlineData("security-stage", "https://vsuh8a8v8i.execute-api.us-west-2.amazonaws.com/security-stage")]
    public void NonProductionCloudActivationRequiresExplicitEnvironment(
        string environment,
        string cloudBaseUrl)
    {
        var prior = Environment.GetEnvironmentVariable("KAEVO_CLOUD_ENVIRONMENT");
        try
        {
            Environment.SetEnvironmentVariable("KAEVO_CLOUD_ENVIRONMENT", environment);
            var activation = KaevoCloudActivationValidator.Validate(
                ValidRequest with { CloudBaseUrl = cloudBaseUrl });
            Assert.Equal(cloudBaseUrl, activation.CloudBaseUrl);
        }
        finally
        {
            Environment.SetEnvironmentVariable("KAEVO_CLOUD_ENVIRONMENT", prior);
        }
    }

    [Fact]
    public void UnknownCloudEnvironmentFailsClosed()
    {
        var prior = Environment.GetEnvironmentVariable("KAEVO_CLOUD_ENVIRONMENT");
        try
        {
            Environment.SetEnvironmentVariable("KAEVO_CLOUD_ENVIRONMENT", "unexpected");
            Assert.Throws<ArgumentException>(() =>
                KaevoCloudActivationValidator.Validate(ValidRequest));
        }
        finally
        {
            Environment.SetEnvironmentVariable("KAEVO_CLOUD_ENVIRONMENT", prior);
        }
    }

    [Fact]
    public void MalformedPairingMaterialIsRejected()
    {
        Assert.Throws<ArgumentException>(() =>
            KaevoCloudActivationValidator.Validate(ValidRequest with { PairingCode = "not-a-code" }));
        Assert.Throws<ArgumentException>(() =>
            KaevoCloudActivationValidator.Validate(ValidRequest with { ConnectorId = "connector-1" }));
    }

    [Fact]
    public void MissingOrWhitespaceCredentialIsRejected()
    {
        Assert.Throws<ArgumentException>(() =>
            KaevoCloudActivationValidator.Validate(ValidRequest with { JellyfinAccessToken = "short" }));
        Assert.Throws<ArgumentException>(() =>
            KaevoCloudActivationValidator.Validate(ValidRequest with { JellyfinAccessToken = "0123456789abcdef 0123456789abcdef" }));
    }
}
