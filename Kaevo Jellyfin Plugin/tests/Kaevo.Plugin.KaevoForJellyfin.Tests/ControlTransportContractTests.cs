using System.Net;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class ControlTransportContractTests
{
    [Fact]
    public void PushProtocolUsesExactSignedClaimRoute()
    {
        Assert.Equal(2, KaevoCloudConnectorService.ConnectorControlProtocolVersion);
        Assert.Equal(
            "/v3/remote-requests/request-1/claim",
            KaevoCloudConnectorService.PairingV3CloudPath("/v1/remote-requests/request-1/claim"));
        Assert.Equal(
            "cloudRemoteRequestClaimHttp409",
            KaevoCloudConnectorService.CloudFailureCategory(
                "/v3/remote-requests/request-1/claim",
                HttpStatusCode.Conflict));
    }

    [Theory]
    [InlineData(0, 60)]
    [InlineData(7, 67)]
    [InlineData(15, 75)]
    [InlineData(99, 75)]
    public void DisconnectedRecoveryIsNeverFasterThanOneMinute(int jitter, int expectedSeconds)
        => Assert.Equal(expectedSeconds, KaevoCloudConnectorService.DisconnectedRecoveryDelay(jitter).TotalSeconds);

    [Theory]
    [InlineData("request-123_ABC", true)]
    [InlineData("", false)]
    [InlineData("../request", false)]
    [InlineData("request/other", false)]
    [InlineData("request?secret=value", false)]
    public void PushRequestIdentifiersAreStrictlyBounded(string requestId, bool expected)
        => Assert.Equal(expected, KaevoCloudConnectorService.IsSafeControlRequestId(requestId));
}
