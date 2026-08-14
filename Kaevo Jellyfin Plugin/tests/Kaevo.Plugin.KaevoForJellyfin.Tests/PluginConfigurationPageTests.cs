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
        Assert.Contains("KaevoRepairPairing", page, StringComparison.Ordinal);
        Assert.Contains("Create a new one-time signed repair QR", page, StringComparison.Ordinal);
        Assert.Contains("Before uninstalling:", page, StringComparison.Ordinal);
        Assert.Contains("SABnzbd", page, StringComparison.Ordinal);
        Assert.Contains("qBittorrent", page, StringComparison.Ordinal);
        Assert.Contains("#KaevoCreatePairing:disabled", page, StringComparison.Ordinal);
        Assert.Contains("#KaevoCreatePairing[data-connected=\"true\"]", page, StringComparison.Ordinal);
        Assert.Contains("button.setAttribute('data-connected', paired ? 'true' : 'false')", page, StringComparison.Ordinal);
        Assert.Contains("background:#0b0d10 !important", page, StringComparison.Ordinal);
        Assert.Contains("background:rgba(8,10,13,.52)", page, StringComparison.Ordinal);
        Assert.Contains("border:1px solid rgba(231,196,139,.45)", page, StringComparison.Ordinal);
        Assert.Contains("#KaevoRepairPairing", page, StringComparison.Ordinal);
        Assert.Contains("background:rgba(8,10,13,.74) !important", page, StringComparison.Ordinal);
        Assert.Contains("#KaevoRepairPairing:focus-visible", page, StringComparison.Ordinal);
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
        Assert.Contains("class=\"fieldDescription kaevo-toggle-description\"", page, StringComparison.Ordinal);
        Assert.Contains("position:static !important", page, StringComparison.Ordinal);
        Assert.Contains("Settings → Connections → Jellyfin Plugins", page, StringComparison.Ordinal);
        Assert.Contains("enable Jellyfin Plugin Integrations and Intro Skipper", page, StringComparison.Ordinal);
        Assert.Contains("type=\"checkbox\" is=\"emby-checkbox\"", page, StringComparison.Ordinal);
        Assert.Contains("input:not([type=\"checkbox\"])", page, StringComparison.Ordinal);
        Assert.Contains("id=\"KaevoSaveConfiguration\"", page, StringComparison.Ordinal);
        Assert.Contains("role=\"status\" aria-live=\"polite\"", page, StringComparison.Ordinal);
        Assert.Contains("setSaveState('saving')", page, StringComparison.Ordinal);
        Assert.Contains("setSaveState(configurationMatchesSavedSettings() ? 'saved' : 'idle')", page, StringComparison.Ordinal);
        Assert.Contains("setSaveState('error')", page, StringComparison.Ordinal);
        Assert.Contains("Saving…", page, StringComparison.Ordinal);
        Assert.Contains("Saved ✓", page, StringComparison.Ordinal);
        Assert.Contains("Settings are saved.", page, StringComparison.Ordinal);
        Assert.Contains("#KaevoSaveConfiguration[data-save-state=\"saved\"]", page, StringComparison.Ordinal);
        Assert.Contains("#KaevoSaveConfiguration { width:100%; box-sizing:border-box; }", page, StringComparison.Ordinal);
        Assert.Contains("background:#0b0d10 !important", page, StringComparison.Ordinal);
        Assert.Contains("addEventListener('input'", page, StringComparison.Ordinal);
        Assert.Contains("addEventListener('change'", page, StringComparison.Ordinal);
        Assert.Contains("savedSettings: null", page, StringComparison.Ordinal);
        Assert.Contains("configurationMatchesSavedSettings", page, StringComparison.Ordinal);
        Assert.Contains("refreshConfigurationSaveState", page, StringComparison.Ordinal);
        Assert.Contains("KaevoConfig.savedSettings = settingsToSave", page, StringComparison.Ordinal);
        Assert.Contains("button.disabled = true", page, StringComparison.Ordinal);
        Assert.DoesNotContain("saveResetTimer", page, StringComparison.Ordinal);
        Assert.Contains("providerSavedSettings: {}", page, StringComparison.Ordinal);
        Assert.Contains("class=\"raised emby-button kaevo-provider-save\"", page, StringComparison.Ordinal);
        Assert.Contains("providerMatchesSavedSettings", page, StringComparison.Ordinal);
        Assert.Contains("refreshProviderSaveStateFromEvent", page, StringComparison.Ordinal);
        Assert.Contains("setProviderSaveState(provider, 'saving')", page, StringComparison.Ordinal);
        Assert.Contains("setProviderSaveState(provider, 'error')", page, StringComparison.Ordinal);
        Assert.Contains(".kaevo-provider-save[data-save-state=\"saved\"]", page, StringComparison.Ordinal);

        Assert.Contains(assembly.GetManifestResourceNames(), name => name.EndsWith("Branding.Kaevo_LogoMark_Transparent.png", StringComparison.Ordinal));
        Assert.Contains(assembly.GetManifestResourceNames(), name => name.EndsWith("Branding.Kaevo_Wordmark_Transparent.png", StringComparison.Ordinal));
    }
}
