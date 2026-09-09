using Kaevo.Plugin.KaevoForJellyfin.Configuration;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class FirebaseRuntimeSelectionTests
{
    [Theory]
    [InlineData("production", false)]
    [InlineData("security-stage", false)]
    [InlineData("unknown", false)]
    [InlineData("development", true)]
    public void EndpointIsLimitedToDevelopment(string environment, bool expected)
    {
        // A conflicting process environment is deliberately fail-closed.
        if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("KAEVO_CLOUD_ENVIRONMENT"))) return;
        Assert.Equal(expected, KaevoFirebaseRuntime.IsSelected(new PluginConfiguration
        { CloudEnvironment = environment, CloudBaseUrl = KaevoFirebaseRuntime.Endpoint }));
    }

    [Theory]
    [InlineData("https://aneohx5ff6.execute-api.us-west-2.amazonaws.com/dev")]
    [InlineData("https://api.kaevo.watch")]
    [InlineData("https://untrusted.example")]
    [InlineData("https://kaevo-development-mobile-9z2mf5rz.wl.gateway.dev?switch=true")]
    public void AwsAndOtherUrlsDoNotSelectFirebase(string endpoint)
    {
        Assert.False(KaevoFirebaseRuntime.IsSelected(new PluginConfiguration
        { CloudEnvironment = "development", CloudBaseUrl = endpoint }));
    }

    [Fact]
    public void PreviewTicketCannotStartNormalTransport()
    {
        var admission = Admission(false);
        Assert.Throws<InvalidOperationException>(() => KaevoFirebaseRuntime.RequireAdmission(admission));
        KaevoFirebaseRuntime.RequireAdmission(Admission(true));
    }

    [Fact]
    public void ExpiredActivatedTicketCannotStartNormalTransport()
    {
        Assert.Throws<InvalidOperationException>(() => KaevoFirebaseRuntime.RequireAdmission(new FirebaseControlAdmission
        { Channel = new string('a', 43), Epoch = new string('b', 32), CustomToken = "synthetic", PushUid = "synthetic",
          ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(-1), ActivationAllowed = true }));
    }

    private static FirebaseControlAdmission Admission(bool active) => new()
    { Channel = new string('a', 43), Epoch = new string('b', 32), CustomToken = "synthetic", PushUid = "synthetic",
      ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(120), ActivationAllowed = active };
}
