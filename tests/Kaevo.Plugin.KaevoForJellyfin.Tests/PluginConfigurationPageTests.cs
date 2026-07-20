using System.Reflection;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class PluginConfigurationPageTests
{
    [Fact]
    public void PairingSurfaceIncludesDecodedResponseBrandingAndLiveExpiry()
    {
        var assembly = typeof(KaevoLocalPairingService).Assembly;
        var resource = Assert.Single(assembly.GetManifestResourceNames(), name => name.EndsWith("Configuration.configPage.html", StringComparison.Ordinal));
        using var stream = assembly.GetManifestResourceStream(resource);
        Assert.NotNull(stream);
        using var reader = new StreamReader(stream!);
        var page = reader.ReadToEnd();

        Assert.Contains("typeof response.json === 'function'", page, StringComparison.Ordinal);
        Assert.Contains("startPairingCountdown(expiresAt)", page, StringComparison.Ordinal);
        Assert.Contains("KaevoPairingCountdown", page, StringComparison.Ordinal);
        Assert.Contains("Here’s your one-time code", page, StringComparison.Ordinal);
        Assert.Contains("class=\"kaevo-card\"", page, StringComparison.Ordinal);
    }
}
