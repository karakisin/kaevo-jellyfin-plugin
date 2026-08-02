using System.Text.Json;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class RemoteCommandCompletionTests
{
    [Fact]
    public void CompletionPreservesTheExactBindingInspectionOperation()
    {
        var request = new CloudRequest(
            RequestId: "request-binding-inspection",
            Method: "COMMAND",
            Provider: "home_server",
            Path: "/commands/jellyfin.inspect_profile_binding_owner",
            Query: null,
            Operation: "jellyfin.inspect_profile_binding_owner",
            Parameters: null);

        var completed = KaevoCloudConnectorService.CompleteCommand(
            request,
            "jellyfin.inspect_profile_binding_owner",
            new { provider = "jellyfin", owner_state = "found" });

        Assert.Equal(200, completed.Status);
        Assert.Equal("request-binding-inspection", completed.Payload.GetProperty("requestId").GetString());
        Assert.Equal("complete", completed.Payload.GetProperty("state").GetString());
        Assert.Equal("jellyfin.inspect_profile_binding_owner", completed.Payload.GetProperty("operation").GetString());
        Assert.Equal("jellyfin", completed.Payload.GetProperty("result").GetProperty("provider").GetString());
    }
}
