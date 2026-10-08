using System.Text.Json;
using Kaevo.Plugin.KaevoForJellyfin.Configuration;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

// Public protocol numbers and readiness only; never return keys, credentials,
// ticket material, connector/account identity, or the configured issuer.
public sealed record KaevoPairingCompatibility(int SchemaVersion, string PluginVersion,
    int[] SupportedProtocols, int[] EnabledProtocols, bool ConfigurationReady)
{
    public static KaevoPairingCompatibility ForConfiguration(PluginConfiguration config, string version)
    {
        var ready = config.PairingV3Enabled && KaevoCloudEndpointPolicy.TryNormalize(config.CloudBaseUrl, config, out _) && HasVerificationConfiguration(config);
        return new(1, version, new[] { 3 }, ready ? new[] { 3 } : Array.Empty<int>(), ready);
    }

    private static bool HasVerificationConfiguration(PluginConfiguration config)
    {
        if (string.IsNullOrWhiteSpace(config.PairingV3CloudAuthorizationIssuer)) return false;
        try
        {
            var keys = JsonSerializer.Deserialize<Dictionary<string, string>>(config.PairingV3CloudAuthorizationVerificationKeysJson);
            return keys is { Count: > 0 and <= 16 } && keys.All(pair =>
                !string.IsNullOrWhiteSpace(pair.Key) && !string.IsNullOrWhiteSpace(pair.Value)
                && KaevoPairingV3Crypto.Base64UrlDecode(pair.Value).Length == 32);
        }
        catch (Exception error) when (error is JsonException or FormatException or ArgumentException or KaevoPairingV3Exception)
        { return false; }
    }
}
