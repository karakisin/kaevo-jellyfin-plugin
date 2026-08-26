using System.Text.Json;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

/// <summary>
/// Resolves the public Cloud trust material used by Pairing V3. Production
/// trust is product-owned and immutable: stale or empty saved configuration is
/// migrated to the public key and issuer compiled into this release.
/// </summary>
internal static class KaevoPairingV3TrustPolicy
{
    internal const string DevelopmentIssuer = "kaevo-cloud-dev";
    internal const string DevelopmentVerificationKeysJson =
        "{\"v3-dev-20260722-1\":\"ZXSpXhgA-w1wnaMbizv4wIgvmrYepas1cnffi1ZMonY\"}";
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
        // An explicit server environment is an operator pin and always wins.
        // Without one, preserve only an exact product-owned trust bundle.
        // This lets an intentionally repaired QA connector stay on QA while
        // every empty, stale, or unknown configuration still defaults to
        // Production.
        if (string.IsNullOrWhiteSpace(environment))
        {
            if (IsCanonicalBundle(configuredKeysJson, configuredIssuer, DevelopmentVerificationKeysJson, DevelopmentIssuer)
                || IsCanonicalBundle(configuredKeysJson, configuredIssuer, ProductionVerificationKeysJson, ProductionIssuer))
            {
                verificationKeysJson = configuredKeysJson!;
                issuer = configuredIssuer!;
                migrated = false;
                return true;
            }

            environment = "production";
        }

        var normalizedEnvironment = KaevoCloudEndpointPolicy.NormalizeEnvironment(environment);
        if (normalizedEnvironment is "production" or "development")
        {
            verificationKeysJson = normalizedEnvironment == "production"
                ? ProductionVerificationKeysJson
                : DevelopmentVerificationKeysJson;
            issuer = normalizedEnvironment == "production"
                ? ProductionIssuer
                : DevelopmentIssuer;
            migrated = !string.Equals(configuredKeysJson, verificationKeysJson, StringComparison.Ordinal)
                || !string.Equals(configuredIssuer, issuer, StringComparison.Ordinal);
            return true;
        }

        var expectedIssuer = normalizedEnvironment switch
        {
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

    /// <summary>
    /// Selects one exact product-owned environment from an authorization JWT.
    /// The token is fully verified later by <see cref="KaevoPairingV3Service"/>;
    /// this parser only chooses which immutable public key, issuer, and Cloud
    /// endpoint the verifier must use. An explicit server environment remains
    /// a hard pin and cannot be changed by a scanned authorization.
    /// </summary>
    internal static bool TryResolveForAuthorization(
        string? authorization,
        out string verificationKeysJson,
        out string issuer,
        out string environment)
        => TryResolveForAuthorization(
            authorization,
            Environment.GetEnvironmentVariable("KAEVO_CLOUD_ENVIRONMENT"),
            out verificationKeysJson,
            out issuer,
            out environment);

    internal static bool TryResolveForAuthorization(
        string? authorization,
        string? configuredEnvironment,
        out string verificationKeysJson,
        out string issuer,
        out string environment)
    {
        verificationKeysJson = string.Empty;
        issuer = string.Empty;
        environment = string.Empty;
        try
        {
            var parts = authorization?.Split('.');
            if (parts is not { Length: 3 }) return false;
            using var header = JsonDocument.Parse(KaevoPairingV3Crypto.Base64UrlDecode(parts[0]));
            using var payload = JsonDocument.Parse(KaevoPairingV3Crypto.Base64UrlDecode(parts[1]));
            if (header.RootElement.GetProperty("alg").GetString() != "EdDSA"
                || header.RootElement.GetProperty("typ").GetString() != "kaevo-pairing-authorization+jwt")
            {
                return false;
            }

            var kid = header.RootElement.GetProperty("kid").GetString();
            var tokenIssuer = payload.RootElement.GetProperty("iss").GetString();
            var selectedEnvironment = (kid, tokenIssuer) switch
            {
                ("v3-dev-20260722-1", DevelopmentIssuer) => "development",
                ("v3-production-20260820-1", ProductionIssuer) => "production",
                _ => string.Empty
            };
            if (selectedEnvironment.Length == 0) return false;

            if (!string.IsNullOrWhiteSpace(configuredEnvironment)
                && KaevoCloudEndpointPolicy.NormalizeEnvironment(configuredEnvironment) != selectedEnvironment)
            {
                return false;
            }

            environment = selectedEnvironment;
            verificationKeysJson = environment == "production"
                ? ProductionVerificationKeysJson
                : DevelopmentVerificationKeysJson;
            issuer = environment == "production" ? ProductionIssuer : DevelopmentIssuer;
            return true;
        }
        catch (Exception exception) when (exception is JsonException
                                          or FormatException
                                          or InvalidOperationException
                                          or KeyNotFoundException
                                          or KaevoPairingV3Exception)
        {
            return false;
        }
    }

    internal static bool TryEnvironmentForIssuer(string? issuer, out string environment)
    {
        environment = issuer switch
        {
            ProductionIssuer => "production",
            DevelopmentIssuer => "development",
            "kaevo-cloud-security-stage" => "security-stage",
            _ => string.Empty
        };
        return environment.Length > 0;
    }

    private static bool IsCanonicalBundle(string? configuredKeysJson, string? configuredIssuer, string keysJson, string issuer)
        => string.Equals(configuredKeysJson, keysJson, StringComparison.Ordinal)
            && string.Equals(configuredIssuer, issuer, StringComparison.Ordinal);

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
