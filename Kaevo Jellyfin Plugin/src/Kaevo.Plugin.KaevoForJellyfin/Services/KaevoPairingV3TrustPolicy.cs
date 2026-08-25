using System.Text.Json;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

/// <summary>
/// Resolves the public Cloud trust material used by Pairing V3. Production
/// trust is product-owned and immutable: stale or empty saved configuration is
/// migrated to the public key and issuer compiled into this release.
/// </summary>
internal static class KaevoPairingV3TrustPolicy
{
    internal const string ProductionIssuer = "kaevo-cloud-production";
    internal const string ProductionVerificationKeysJson =
        "{\"v3-production-20260820-1\":\"_IzdDgG5yLqvNEgQxjH5cm85b1nxuF98u85ENH-GLj8\"}";

    internal static bool TryResolve(
        string? configuredKeysJson,
        string? configuredIssuer,
        out string verificationKeysJson,
        out string issuer,
        out bool migrated)
        => TryResolve(
            configuredKeysJson,
            configuredIssuer,
            Environment.GetEnvironmentVariable("KAEVO_CLOUD_ENVIRONMENT"),
            out verificationKeysJson,
            out issuer,
            out migrated);

    internal static bool TryResolve(
        string? configuredKeysJson,
        string? configuredIssuer,
        string? environment,
        out string verificationKeysJson,
        out string issuer,
        out bool migrated)
    {
        var normalizedEnvironment = KaevoCloudEndpointPolicy.NormalizeEnvironment(environment);
        if (normalizedEnvironment == "production")
        {
            verificationKeysJson = ProductionVerificationKeysJson;
            issuer = ProductionIssuer;
            migrated = !string.Equals(configuredKeysJson, verificationKeysJson, StringComparison.Ordinal)
                || !string.Equals(configuredIssuer, issuer, StringComparison.Ordinal);
            return true;
        }

        var expectedIssuer = normalizedEnvironment switch
        {
            "development" => "kaevo-cloud-dev",
            "security-stage" => "kaevo-cloud-security-stage",
            _ => string.Empty
        };
        if (expectedIssuer.Length == 0
            || !string.Equals(configuredIssuer, expectedIssuer, StringComparison.Ordinal)
            || !ContainsUsablePublicKey(configuredKeysJson))
        {
            verificationKeysJson = string.Empty;
            issuer = string.Empty;
            migrated = false;
            return false;
        }

        verificationKeysJson = configuredKeysJson!;
        issuer = configuredIssuer!;
        migrated = false;
        return true;
    }

    private static bool ContainsUsablePublicKey(string? value)
    {
        try
        {
            var keys = JsonSerializer.Deserialize<Dictionary<string, string>>(
                value ?? string.Empty,
                new JsonSerializerOptions(JsonSerializerDefaults.Web));
            return keys is { Count: > 0 }
                && keys.All(entry => !string.IsNullOrWhiteSpace(entry.Key)
                    && TryDecode(entry.Value, out var key)
                    && key.Length == 32);
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static bool TryDecode(string value, out byte[] bytes)
    {
        try
        {
            var padded = value.Replace('-', '+').Replace('_', '/')
                + new string('=', (4 - value.Length % 4) % 4);
            bytes = Convert.FromBase64String(padded);
            return true;
        }
        catch (FormatException)
        {
            bytes = [];
            return false;
        }
    }
}
