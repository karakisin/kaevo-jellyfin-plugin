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
        var pageBody = page.IndexOf("<div id=\"KaevoConfigPage\"", StringComparison.Ordinal);
        var injectedStyles = page.IndexOf("<style id=\"KaevoInjectedStyles\">", StringComparison.Ordinal);
        Assert.True(injectedStyles > pageBody, "Kaevo styles must live inside the body fragment Jellyfin injects.");
        Assert.Contains("text-align:center", page, StringComparison.Ordinal);
        Assert.Contains("loadKaevoBranding()", page, StringComparison.Ordinal);
        Assert.Contains("Private at home.", page, StringComparison.Ordinal);
        Assert.Contains("Nothing extra.", page, StringComparison.Ordinal);
        Assert.Contains("#KaevoConfigForm { width:100%; max-width:none; margin:0; }", page, StringComparison.Ordinal);

        Assert.Contains(assembly.GetManifestResourceNames(), name => name.EndsWith("Branding.Kaevo_LogoMark_Transparent.png", StringComparison.Ordinal));
        Assert.Contains(assembly.GetManifestResourceNames(), name => name.EndsWith("Branding.Kaevo_Wordmark_Transparent.png", StringComparison.Ordinal));
    }
}
