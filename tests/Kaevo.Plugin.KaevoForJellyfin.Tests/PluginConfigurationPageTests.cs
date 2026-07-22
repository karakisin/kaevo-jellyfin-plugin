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
        Assert.Contains("kaevo/v3/pairing/start", page, StringComparison.Ordinal);
        Assert.Contains("kaevo/v3/pairing/status", page, StringComparison.Ordinal);
        Assert.Contains("System/Info/Public", page, StringComparison.Ordinal);
        Assert.Contains("config.PairingV3Enabled === true || config.pairingV3Enabled === true", page, StringComparison.Ordinal);
        Assert.Contains("Create New Pairing V3 QR", page, StringComparison.Ordinal);
        Assert.Contains("Kaevo App Connected", page, StringComparison.Ordinal);
        Assert.Contains("button.disabled = paired", page, StringComparison.Ordinal);
        Assert.Contains("KaevoConfig.pairingV3Connected", page, StringComparison.Ordinal);
        Assert.Contains("#KaevoCreatePairing:disabled", page, StringComparison.Ordinal);
        Assert.Contains("#KaevoCreatePairing[data-connected=\"true\"]", page, StringComparison.Ordinal);
        Assert.Contains("button.setAttribute('data-connected', paired ? 'true' : 'false')", page, StringComparison.Ordinal);
        Assert.Contains("background:#0b0d10 !important", page, StringComparison.Ordinal);
        Assert.Contains("background:rgba(8,10,13,.52)", page, StringComparison.Ordinal);
        Assert.Contains("border:1px solid rgba(231,196,139,.45)", page, StringComparison.Ordinal);
        Assert.Contains("Scan this signed Pairing V3 QR in Kaevo.", page, StringComparison.Ordinal);
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
        Assert.Contains("class=\"kaevo-toggle-row\"", page, StringComparison.Ordinal);
        Assert.Contains("type=\"checkbox\" is=\"emby-checkbox\"", page, StringComparison.Ordinal);
        Assert.Contains("input:not([type=\"checkbox\"])", page, StringComparison.Ordinal);

        Assert.Contains(assembly.GetManifestResourceNames(), name => name.EndsWith("Branding.Kaevo_LogoMark_Transparent.png", StringComparison.Ordinal));
        Assert.Contains(assembly.GetManifestResourceNames(), name => name.EndsWith("Branding.Kaevo_Wordmark_Transparent.png", StringComparison.Ordinal));
    }
}
