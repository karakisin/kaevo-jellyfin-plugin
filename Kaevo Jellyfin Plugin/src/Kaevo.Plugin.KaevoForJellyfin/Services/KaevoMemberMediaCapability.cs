using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

/// <summary>
/// Verifies the Cloud-issued capability used by the username-auth member
/// media surface.  It deliberately contains only opaque handles: the app
/// cannot learn or select a Jellyfin identity from a capability.
/// </summary>
internal sealed record KaevoMemberMediaCapabilityContext(
    string ConnectorId,
    string ProfileId,
    string PrincipalHandle,
    string HouseholdHandle,
    string DeviceInstallationHandle,
    IReadOnlyCollection<string> RequiredScopes,
    string? BindingsJson);

internal sealed record KaevoResolvedMemberMediaCapability(
    string JellyfinUserId,
    string GrantId,
    long ExpiresAt,
    IReadOnlySet<string> Scopes);

internal static partial class KaevoMemberMediaCapabilityVerifier
{
    internal const string Audience = "kaevo-home-connectors-member-media-v1";
    internal const string Type = "kaevo-member-media-capability+jwt";
    private const int Version = 1;
    private const long MaximumLifetimeSeconds = 10 * 60;
    private const long MaximumClockSkewSeconds = 60;
    private static readonly HashSet<string> SupportedScopes = new(StringComparer.Ordinal)
    {
        "metadata.read", "library.read", "search.read", "playback.start",
        "playback.report", "progress.read", "progress.write"
    };

    internal static KaevoResolvedMemberMediaCapability Verify(
        string? encodedCapability,
        KaevoMemberMediaCapabilityContext context,
        string verificationKeysJson,
        string expectedIssuer,
        long? nowEpoch = null)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(encodedCapability)
                || string.IsNullOrWhiteSpace(expectedIssuer)
                || !KaevoProfileJellyfinBindingStore.ValidMemberCapabilityContext(context))
            {
                throw new InvalidOperationException();
            }

            var parts = encodedCapability.Split('.');
            if (parts.Length != 3 || parts.Any(part => string.IsNullOrWhiteSpace(part)))
            {
                throw new InvalidOperationException();
            }

            using var header = JsonDocument.Parse(KaevoPairingV3Crypto.Base64UrlDecode(parts[0]));
            using var claims = JsonDocument.Parse(KaevoPairingV3Crypto.Base64UrlDecode(parts[1]));
            var headerRoot = header.RootElement;
            var root = claims.RootElement;
            if (headerRoot.ValueKind != JsonValueKind.Object
                || root.ValueKind != JsonValueKind.Object
                || headerRoot.GetProperty("alg").GetString() != "EdDSA"
                || headerRoot.GetProperty("typ").GetString() != Type)
            {
                throw new InvalidOperationException();
            }

            var keyId = RequiredString(headerRoot, "kid");
            var verificationKeys = JsonSerializer.Deserialize<Dictionary<string, string>>(
                verificationKeysJson,
                new JsonSerializerOptions(JsonSerializerDefaults.Web));
            if (verificationKeys is null
                || !verificationKeys.TryGetValue(keyId, out var encodedKey)
                || !KaevoPairingV3Crypto.Verify(
                    KaevoPairingV3Crypto.Base64UrlDecode(encodedKey),
                    Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]),
                    parts[2]))
            {
                throw new InvalidOperationException();
            }

            // A capability is an opaque, signed assertion. Reject accidental
            // introduction of a raw provider identity before it can reach an
            // iOS response or a local provider request.
            foreach (var forbidden in new[] { "jellyfin_user_id", "provider_user_id", "connector_id", "profile_id", "principal_id", "household_id", "device_id" })
            {
                if (root.TryGetProperty(forbidden, out _))
                {
                    throw new InvalidOperationException();
                }
            }

            if (RequiredString(root, "iss") != expectedIssuer
                || RequiredString(root, "aud") != Audience
                || RequiredString(root, "protocol") != KaevoPairingV3Crypto.Protocol
                || RequiredString(root, "capability_type") != "member_media"
                || RequiredInt(root, "v") != Version)
            {
                throw new InvalidOperationException();
            }

            var now = nowEpoch ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var issuedAt = RequiredInt64(root, "iat");
            var notBefore = RequiredInt64(root, "nbf");
            var expiresAt = RequiredInt64(root, "exp");
            if (issuedAt > now + MaximumClockSkewSeconds
                || notBefore > issuedAt
                || expiresAt <= issuedAt
                || expiresAt - issuedAt > MaximumLifetimeSeconds
                || now < notBefore
                || now >= expiresAt)
            {
                throw new InvalidOperationException();
            }

            var grantId = RequiredString(root, "jti");
            if (!GrantIdRegex().IsMatch(grantId))
            {
                throw new InvalidOperationException();
            }

            RequireOpaqueMatch(RequiredString(root, "connector_handle"), KaevoProfileJellyfinBindingStore.OpaqueHandle("connector", context.ConnectorId));
            RequireOpaqueMatch(RequiredString(root, "profile_handle"), KaevoProfileJellyfinBindingStore.OpaqueHandle("profile", context.ProfileId));
            RequireOpaqueMatch(RequiredString(root, "principal_handle"), context.PrincipalHandle);
            RequireOpaqueMatch(RequiredString(root, "household_handle"), context.HouseholdHandle);
            RequireOpaqueMatch(RequiredString(root, "device_installation_handle"), context.DeviceInstallationHandle);

            var bindingHandle = RequiredString(root, "binding_handle");
            var bindingRevision = RequiredString(root, "binding_revision");
            if (!KaevoProfileJellyfinBindingStore.TryResolveMemberCapabilityBinding(
                    context.BindingsJson,
                    context.ProfileId,
                    bindingHandle,
                    bindingRevision,
                    out var jellyfinUserId))
            {
                throw new InvalidOperationException();
            }

            var scopes = ReadScopes(root);
            if (!context.RequiredScopes.All(scopes.Contains))
            {
                throw new InvalidOperationException();
            }

            return new KaevoResolvedMemberMediaCapability(jellyfinUserId, grantId, expiresAt, scopes);
        }
        catch (Exception)
        {
            throw new InvalidOperationException("memberMediaCapabilityInvalid");
        }
    }

    private static HashSet<string> ReadScopes(JsonElement root)
    {
        if (!root.TryGetProperty("scope", out var scope)
            || scope.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidOperationException();
        }

        var values = new HashSet<string>(StringComparer.Ordinal);
        foreach (var value in scope.EnumerateArray())
        {
            if (value.ValueKind != JsonValueKind.String
                || !SupportedScopes.Contains(value.GetString() ?? string.Empty)
                || !values.Add(value.GetString()!))
            {
                throw new InvalidOperationException();
            }
        }
        if (values.Count == 0)
        {
            throw new InvalidOperationException();
        }
        return values;
    }

    private static void RequireOpaqueMatch(string actual, string expected)
    {
        if (!OpaqueHandleRegex().IsMatch(actual)
            || !CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(actual), Encoding.ASCII.GetBytes(expected)))
        {
            throw new InvalidOperationException();
        }
    }

    private static string RequiredString(JsonElement root, string name)
        => root.TryGetProperty(name, out var value)
            && value.ValueKind == JsonValueKind.String
            && !string.IsNullOrWhiteSpace(value.GetString())
            ? value.GetString()!
            : throw new InvalidOperationException();

    private static int RequiredInt(JsonElement root, string name)
        => root.TryGetProperty(name, out var value) && value.TryGetInt32(out var result)
            ? result
            : throw new InvalidOperationException();

    private static long RequiredInt64(JsonElement root, string name)
        => root.TryGetProperty(name, out var value) && value.TryGetInt64(out var result)
            ? result
            : throw new InvalidOperationException();

    [GeneratedRegex("^[A-Za-z0-9_-]{16,128}$", RegexOptions.CultureInvariant)]
    private static partial Regex GrantIdRegex();

    [GeneratedRegex("^sha256:[A-Za-z0-9_-]{43}$", RegexOptions.CultureInvariant)]
    private static partial Regex OpaqueHandleRegex();
}

/// <summary>Validates the minimal local Jellyfin user status needed by a member capability.</summary>
internal static class KaevoMemberMediaUserState
{
    internal static bool IsActive(JsonElement user)
    {
        if (user.ValueKind != JsonValueKind.Object)
        {
            return false;
        }
        if (user.TryGetProperty("IsDisabled", out var disabled)
            && disabled.ValueKind is JsonValueKind.True or JsonValueKind.False
            && disabled.GetBoolean())
        {
            return false;
        }
        if (user.TryGetProperty("Policy", out var policy)
            && policy.ValueKind == JsonValueKind.Object
            && policy.TryGetProperty("IsDisabled", out disabled)
            && disabled.ValueKind is JsonValueKind.True or JsonValueKind.False
            && disabled.GetBoolean())
        {
            return false;
        }
        // A returned user without an enabled flag is treated as active; an
        // absent/deleted user is rejected by the exact local GET above.
        return true;
    }
}
