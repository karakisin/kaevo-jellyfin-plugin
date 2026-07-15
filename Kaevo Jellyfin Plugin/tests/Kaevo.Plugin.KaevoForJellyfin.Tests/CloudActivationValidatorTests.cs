using Kaevo.Plugin.KaevoForJellyfin.Models;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class CloudActivationValidatorTests
{
    private static readonly KaevoCloudActivationRequest ValidRequest = new(
        "https://aneohx5ff6.execute-api.us-west-2.amazonaws.com/dev",
        "profile_stub",
        "123e4567-e89b-42d3-a456-426614174000",
        "ABCD-1234-EF56",
        "bf37113a073e40e8a22cd100cb3b8ac2",
        "0123456789abcdef0123456789abcdef");

    [Fact]
    public void OfficialCloudActivationIsAccepted()
    {
        var activation = KaevoCloudActivationValidator.Validate(ValidRequest);

        Assert.Equal("https://aneohx5ff6.execute-api.us-west-2.amazonaws.com/dev", activation.CloudBaseUrl);
        Assert.Equal("ABCD-1234-EF56", activation.PairingCode);
    }

    [Theory]
    [InlineData("http://aneohx5ff6.execute-api.us-west-2.amazonaws.com/dev")]
    [InlineData("https://127.0.0.1/dev")]
    [InlineData("https://example.com/dev")]
    [InlineData("https://kaevo.app.evil.example/dev")]
    public void UnapprovedCloudDestinationsAreRejected(string cloudBaseUrl)
    {
        Assert.Throws<ArgumentException>(() =>
            KaevoCloudActivationValidator.Validate(ValidRequest with { CloudBaseUrl = cloudBaseUrl }));
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
