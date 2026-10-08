using Kaevo.Plugin.KaevoForJellyfin.Configuration;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

/// <summary>Release-owned bootstrap trust, never a connected state or entitlement.</summary>
internal static class KaevoNativePairingConfiguration
{
    internal const string Origin = "https://kaevo-development-mobile-9z2mf5rz.wl.gateway.dev";
    internal const string Issuer = "kaevo-cloud-dev";
    internal const string KeyId = "v3-dev-20260722-1";
    internal const string PublicKey = "ZXSpXhgA-w1wnaMbizv4wIgvmrYepas1cnffi1ZMonY";

    internal static bool IsNative(Uri origin) => origin.AbsoluteUri.TrimEnd('/') == Origin;

    internal static bool ApplyToUnconfigured(PluginConfiguration configuration)
    {
        // Existing, paused, migrated, or administrator-configured installations
        // keep their explicit endpoint and trust policy.
        if (configuration.CloudConnectorEnabled || configuration.PairingV3Enabled
            || !string.IsNullOrWhiteSpace(configuration.CloudBaseUrl)
            || !string.IsNullOrWhiteSpace(configuration.CloudEnvironment)
            || !string.IsNullOrWhiteSpace(configuration.ConnectorId)
            || !string.IsNullOrWhiteSpace(configuration.ProfileId)
            || !string.IsNullOrWhiteSpace(configuration.JellyfinUserId)
            || !string.IsNullOrWhiteSpace(configuration.ProfileJellyfinBindingsJson)
            || !string.IsNullOrWhiteSpace(configuration.PairingV3CloudAuthorizationIssuer)
            || !string.IsNullOrWhiteSpace(configuration.PairingV3CloudAuthorizationVerificationKeysJson)) return false;
        configuration.CloudBaseUrl = Origin;
        configuration.CloudEnvironment = "development";
        configuration.PairingV3CloudAuthorizationIssuer = Issuer;
        configuration.PairingV3CloudAuthorizationVerificationKeysJson = System.Text.Json.JsonSerializer.Serialize(
            new Dictionary<string, string> { [KeyId] = PublicKey });
        configuration.PairingV3Enabled = true;
        return true;
    }
}
