using System.Text.Json;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public class FirebaseHeartbeatCapabilitiesTests
{
    [Fact]
    public void FirstHeartbeatAdvertisesCurrentMediaAndPushProtocolWithoutRegistration()
    {
        var body = JsonSerializer.SerializeToElement(KaevoCloudConnectorService.HeartbeatBody(
            "exact-connector", "exact-profile", new { jellyfin = new { configured = true } }));
        Assert.Equal("exact-connector", body.GetProperty("connector_id").GetString());
        Assert.Equal("exact-profile", body.GetProperty("profile_id").GetString());
        Assert.Equal(KaevoPlugin.BuildVersion, body.GetProperty("app_version").GetString());
        var capabilities = body.GetProperty("capabilities").EnumerateArray().Select(v => v.GetString()).ToArray();
        Assert.Contains("connector_control_push_v2", capabilities);
        Assert.Contains("remote_metadata_v1", capabilities);
        Assert.Contains("direct_play", capabilities);
        Assert.True(body.GetProperty("provider_status").GetProperty("jellyfin").GetProperty("configured").GetBoolean());
    }
}
