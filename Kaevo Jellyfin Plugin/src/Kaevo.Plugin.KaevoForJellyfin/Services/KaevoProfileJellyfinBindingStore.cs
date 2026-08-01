using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Kaevo.Plugin.KaevoForJellyfin.Configuration;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

internal enum KaevoProfileJellyfinBindingWriteResult
{
    Bound,
    InvalidRequest,
    BindingStoreInvalid,
    BindingCapacityReached,
    JellyfinUserAlreadyBound
}

internal enum KaevoProfileJellyfinBindingOwnerLookupResult
{
    Found,
    Missing,
    InvalidRequest,
    BindingStoreInvalid,
    Ambiguous
}

internal enum KaevoProfileJellyfinBindingReassignmentResult
{
    Reassigned,
    AlreadyBound,
    InvalidRequest,
    BindingStoreInvalid,
    BindingCapacityReached,
    OwnerMismatch,
    OwnerAmbiguous,
    TargetAlreadyBound
}

internal enum KaevoProfileJellyfinBindingUnboundClaimInspectionResult
{
    Eligible,
    AlreadyBound,
    OwnerFound,
    TargetConflict,
    BindingStoreInvalid,
    OwnerAmbiguous,
    InvalidRequest
}

internal enum KaevoProfileJellyfinBindingUnboundClaimResult
{
    Claimed,
    AlreadyBound,
    InvalidRequest,
    BindingStoreInvalid,
    BindingRevisionMismatch,
    BindingCapacityReached,
    OwnerConflict,
    OwnerAmbiguous,
    TargetAlreadyBound
}

internal static class KaevoProfileJellyfinBindingStore
{
    private const int MaximumBindings = 256;

    internal static bool TryResolve(
        PluginConfiguration configuration,
        string? cloudProfileId,
        out string jellyfinUserId) =>
        TryResolve(
            configuration.ProfileJellyfinBindingsJson,
            configuration.ProfileId,
            configuration.JellyfinUserId,
            cloudProfileId,
            out jellyfinUserId);

    internal static bool TryResolve(
        string? bindingsJson,
        string? pairedProfileId,
        string? pairedJellyfinUserId,
        string? cloudProfileId,
        out string jellyfinUserId)
    {
        jellyfinUserId = string.Empty;
        if (!ValidProfileId(cloudProfileId))
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(bindingsJson))
        {
            if (!TryRead(bindingsJson, out var bindings))
            {
                // An authoritative map that cannot be parsed is unsafe. Do not
                // fall back to the connector owner.
                return false;
            }

            return bindings.TryGetValue(cloudProfileId!, out var mappedUserId)
                && TryNormalizeJellyfinUserId(mappedUserId, out jellyfinUserId);
        }

        // Compatibility is deliberately restricted to the original paired
        // profile. A fresh member can never inherit this identity.
        return string.Equals(cloudProfileId, pairedProfileId, StringComparison.Ordinal)
            && TryNormalizeJellyfinUserId(pairedJellyfinUserId, out jellyfinUserId);
    }

    internal static bool TryBind(
        PluginConfiguration configuration,
        string? cloudProfileId,
        string? jellyfinUserId) =>
        TryBindWithResult(configuration, cloudProfileId, jellyfinUserId)
            == KaevoProfileJellyfinBindingWriteResult.Bound;

    /// <summary>
    /// Persists one exact Cloud-profile-to-Jellyfin-user binding and preserves
    /// a non-identifying failure state when it cannot be saved.
    /// </summary>
    internal static KaevoProfileJellyfinBindingWriteResult TryBindWithResult(
        PluginConfiguration configuration,
        string? cloudProfileId,
        string? jellyfinUserId)
    {
        var result = TryBindWithResult(
                configuration.ProfileJellyfinBindingsJson,
                cloudProfileId,
                jellyfinUserId,
                out var updatedBindingsJson);
        if (result != KaevoProfileJellyfinBindingWriteResult.Bound)
        {
            return result;
        }

        configuration.ProfileJellyfinBindingsJson = updatedBindingsJson;
        return KaevoProfileJellyfinBindingWriteResult.Bound;
    }

    internal static bool TryBind(
        string? bindingsJson,
        string? cloudProfileId,
        string? jellyfinUserId,
        out string updatedBindingsJson) =>
        TryBindWithResult(bindingsJson, cloudProfileId, jellyfinUserId, out updatedBindingsJson)
            == KaevoProfileJellyfinBindingWriteResult.Bound;

    internal static KaevoProfileJellyfinBindingWriteResult TryBindWithResult(
        string? bindingsJson,
        string? cloudProfileId,
        string? jellyfinUserId,
        out string updatedBindingsJson)
    {
        updatedBindingsJson = bindingsJson ?? string.Empty;
        if (!ValidProfileId(cloudProfileId)
            || !TryNormalizeJellyfinUserId(jellyfinUserId, out var normalizedUserId))
        {
            return KaevoProfileJellyfinBindingWriteResult.InvalidRequest;
        }

        Dictionary<string, string> bindings;
        if (string.IsNullOrWhiteSpace(bindingsJson))
        {
            bindings = new Dictionary<string, string>(StringComparer.Ordinal);
        }
        else if (!TryRead(bindingsJson, out bindings))
        {
            return KaevoProfileJellyfinBindingWriteResult.BindingStoreInvalid;
        }

        if (!bindings.ContainsKey(cloudProfileId!) && bindings.Count >= MaximumBindings)
        {
            return KaevoProfileJellyfinBindingWriteResult.BindingCapacityReached;
        }

        if (bindings.Any(entry =>
                !string.Equals(entry.Key, cloudProfileId, StringComparison.Ordinal)
                && string.Equals(entry.Value, normalizedUserId, StringComparison.Ordinal)))
        {
            // One Jellyfin identity can back only one Cloud profile. Sharing
            // it would merge profile-scoped libraries, playback, and policy.
            return KaevoProfileJellyfinBindingWriteResult.JellyfinUserAlreadyBound;
        }

        bindings[cloudProfileId!] = normalizedUserId;
        updatedBindingsJson = JsonSerializer.Serialize(
            bindings.OrderBy(entry => entry.Key, StringComparer.Ordinal)
                .ToDictionary(entry => entry.Key, entry => entry.Value, StringComparer.Ordinal));
        return KaevoProfileJellyfinBindingWriteResult.Bound;
    }

    internal static string ProfileBindingState(PluginConfiguration configuration) =>
        ProfileBindingState(configuration.ProfileJellyfinBindingsJson);

    internal static string ProfileBindingState(string? bindingsJson) =>
        string.IsNullOrWhiteSpace(bindingsJson)
            || TryRead(bindingsJson, out _)
            ? "ready"
            : "binding_store_invalid";

    internal static string ResponseState(KaevoProfileJellyfinBindingWriteResult result) => result switch
    {
        KaevoProfileJellyfinBindingWriteResult.Bound => "bound",
        KaevoProfileJellyfinBindingWriteResult.InvalidRequest => "invalid_request",
        KaevoProfileJellyfinBindingWriteResult.BindingStoreInvalid => "binding_store_invalid",
        KaevoProfileJellyfinBindingWriteResult.BindingCapacityReached => "binding_capacity_reached",
        KaevoProfileJellyfinBindingWriteResult.JellyfinUserAlreadyBound => "jellyfin_user_already_bound",
        _ => "invalid_request"
    };

    internal static bool TryUnbind(
        PluginConfiguration configuration,
        string? cloudProfileId,
        string? jellyfinUserId)
    {
        if (!TryUnbind(
                configuration.ProfileJellyfinBindingsJson,
                cloudProfileId,
                jellyfinUserId,
                out var updatedBindingsJson))
        {
            return false;
        }

        configuration.ProfileJellyfinBindingsJson = updatedBindingsJson;
        return true;
    }

    internal static KaevoProfileJellyfinBindingOwnerLookupResult FindExactOwner(
        string? bindingsJson,
        string? jellyfinUserId,
        out string sourceProfileId)
    {
        sourceProfileId = string.Empty;
        if (!TryNormalizeJellyfinUserId(jellyfinUserId, out var normalizedUserId))
        {
            return KaevoProfileJellyfinBindingOwnerLookupResult.InvalidRequest;
        }

        if (string.IsNullOrWhiteSpace(bindingsJson))
        {
            return KaevoProfileJellyfinBindingOwnerLookupResult.Missing;
        }
        if (!TryRead(bindingsJson, out var bindings))
        {
            return KaevoProfileJellyfinBindingOwnerLookupResult.BindingStoreInvalid;
        }

        var owners = bindings
            .Where(entry => string.Equals(entry.Value, normalizedUserId, StringComparison.Ordinal))
            .Select(entry => entry.Key)
            .Take(2)
            .ToArray();
        if (owners.Length == 0)
        {
            return KaevoProfileJellyfinBindingOwnerLookupResult.Missing;
        }
        if (owners.Length != 1)
        {
            return KaevoProfileJellyfinBindingOwnerLookupResult.Ambiguous;
        }

        sourceProfileId = owners[0];
        return KaevoProfileJellyfinBindingOwnerLookupResult.Found;
    }

    internal static KaevoProfileJellyfinBindingUnboundClaimInspectionResult InspectUnboundClaim(
        string? bindingsJson,
        string? targetProfileId,
        string? jellyfinUserId,
        out string sourceProfileId,
        out string bindingRevision)
    {
        sourceProfileId = string.Empty;
        bindingRevision = BindingRevision(bindingsJson);
        if (!ValidProfileId(targetProfileId)
            || !TryNormalizeJellyfinUserId(jellyfinUserId, out var normalizedUserId))
        {
            return KaevoProfileJellyfinBindingUnboundClaimInspectionResult.InvalidRequest;
        }
        if (!TryReadOrEmpty(bindingsJson, out var bindings))
        {
            return KaevoProfileJellyfinBindingUnboundClaimInspectionResult.BindingStoreInvalid;
        }
        var owners = bindings.Where(entry => string.Equals(entry.Value, normalizedUserId, StringComparison.Ordinal))
            .Select(entry => entry.Key).Take(2).ToArray();
        if (owners.Length > 1)
        {
            return KaevoProfileJellyfinBindingUnboundClaimInspectionResult.OwnerAmbiguous;
        }
        if (bindings.TryGetValue(targetProfileId!, out var targetUserId)
            && !string.Equals(targetUserId, normalizedUserId, StringComparison.Ordinal))
        {
            return KaevoProfileJellyfinBindingUnboundClaimInspectionResult.TargetConflict;
        }
        if (owners.Length == 1 && string.Equals(owners[0], targetProfileId, StringComparison.Ordinal))
        {
            sourceProfileId = targetProfileId!;
            return KaevoProfileJellyfinBindingUnboundClaimInspectionResult.AlreadyBound;
        }
        if (owners.Length == 1)
        {
            sourceProfileId = owners[0];
            return KaevoProfileJellyfinBindingUnboundClaimInspectionResult.OwnerFound;
        }
        return KaevoProfileJellyfinBindingUnboundClaimInspectionResult.Eligible;
    }

    internal static KaevoProfileJellyfinBindingUnboundClaimResult TryClaimUnboundUser(
        PluginConfiguration configuration,
        string? expectedBindingRevision,
        string? targetProfileId,
        string? jellyfinUserId,
        string? bindingOperationId)
    {
        var result = TryClaimUnboundUser(
            configuration.ProfileJellyfinBindingsJson,
            configuration.ProfileJellyfinBindingClaimOperationsJson,
            expectedBindingRevision,
            targetProfileId,
            jellyfinUserId,
            bindingOperationId,
            out var updatedBindingsJson,
            out var updatedClaimOperationsJson);
        if (result == KaevoProfileJellyfinBindingUnboundClaimResult.Claimed)
        {
            configuration.ProfileJellyfinBindingsJson = updatedBindingsJson;
            configuration.ProfileJellyfinBindingClaimOperationsJson = updatedClaimOperationsJson;
        }
        return result;
    }

    internal static KaevoProfileJellyfinBindingUnboundClaimResult TryClaimUnboundUser(
        string? bindingsJson,
        string? claimOperationsJson,
        string? expectedBindingRevision,
        string? targetProfileId,
        string? jellyfinUserId,
        string? bindingOperationId,
        out string updatedBindingsJson,
        out string updatedClaimOperationsJson)
    {
        updatedBindingsJson = bindingsJson ?? string.Empty;
        updatedClaimOperationsJson = claimOperationsJson ?? string.Empty;
        if (!ValidProfileId(targetProfileId)
            || !TryNormalizeJellyfinUserId(jellyfinUserId, out var normalizedUserId)
            || string.IsNullOrWhiteSpace(bindingOperationId)
            || bindingOperationId.Length > 128)
        {
            return KaevoProfileJellyfinBindingUnboundClaimResult.InvalidRequest;
        }
        if (!TryReadOrEmpty(bindingsJson, out var bindings)
            || !TryReadClaimOperations(claimOperationsJson, out var operations))
        {
            return KaevoProfileJellyfinBindingUnboundClaimResult.BindingStoreInvalid;
        }
        var owners = bindings.Where(entry => string.Equals(entry.Value, normalizedUserId, StringComparison.Ordinal))
            .Select(entry => entry.Key).Take(2).ToArray();
        if (owners.Length > 1)
        {
            return KaevoProfileJellyfinBindingUnboundClaimResult.OwnerAmbiguous;
        }
        if (bindings.TryGetValue(targetProfileId!, out var targetUserId))
        {
            return string.Equals(targetUserId, normalizedUserId, StringComparison.Ordinal)
                && owners.Length == 1 && string.Equals(owners[0], targetProfileId, StringComparison.Ordinal)
                ? KaevoProfileJellyfinBindingUnboundClaimResult.AlreadyBound
                : KaevoProfileJellyfinBindingUnboundClaimResult.TargetAlreadyBound;
        }
        if (!string.Equals(BindingRevision(bindingsJson), expectedBindingRevision, StringComparison.Ordinal))
        {
            return KaevoProfileJellyfinBindingUnboundClaimResult.BindingRevisionMismatch;
        }
        if (owners.Length != 0)
        {
            return KaevoProfileJellyfinBindingUnboundClaimResult.OwnerConflict;
        }
        if (bindings.Count >= MaximumBindings)
        {
            return KaevoProfileJellyfinBindingUnboundClaimResult.BindingCapacityReached;
        }
        bindings[targetProfileId!] = normalizedUserId;
        operations[targetProfileId!] = OperationFingerprint(bindingOperationId);
        updatedBindingsJson = Serialize(bindings);
        updatedClaimOperationsJson = SerializeClaimOperations(operations);
        return KaevoProfileJellyfinBindingUnboundClaimResult.Claimed;
    }

    internal static KaevoProfileJellyfinBindingReassignmentResult TryReassignExactOwner(
        PluginConfiguration configuration,
        string? expectedSourceProfileId,
        string? targetProfileId,
        string? jellyfinUserId)
    {
        var result = TryReassignExactOwner(
            configuration.ProfileJellyfinBindingsJson,
            expectedSourceProfileId,
            targetProfileId,
            jellyfinUserId,
            out var updatedBindingsJson);
        if (result == KaevoProfileJellyfinBindingReassignmentResult.Reassigned)
        {
            configuration.ProfileJellyfinBindingsJson = updatedBindingsJson;
        }
        return result;
    }

    internal static KaevoProfileJellyfinBindingReassignmentResult TryReassignExactOwner(
        string? bindingsJson,
        string? expectedSourceProfileId,
        string? targetProfileId,
        string? jellyfinUserId,
        out string updatedBindingsJson)
    {
        updatedBindingsJson = bindingsJson ?? string.Empty;
        if (!ValidProfileId(targetProfileId)
            || !TryNormalizeJellyfinUserId(jellyfinUserId, out var normalizedUserId)
            || (!string.IsNullOrWhiteSpace(expectedSourceProfileId)
                && !ValidProfileId(expectedSourceProfileId)))
        {
            return KaevoProfileJellyfinBindingReassignmentResult.InvalidRequest;
        }

        Dictionary<string, string> bindings;
        if (string.IsNullOrWhiteSpace(bindingsJson))
        {
            bindings = new Dictionary<string, string>(StringComparer.Ordinal);
        }
        else if (!TryRead(bindingsJson, out bindings))
        {
            return KaevoProfileJellyfinBindingReassignmentResult.BindingStoreInvalid;
        }

        var owners = bindings
            .Where(entry => string.Equals(entry.Value, normalizedUserId, StringComparison.Ordinal))
            .Select(entry => entry.Key)
            .Take(2)
            .ToArray();
        if (owners.Length > 1)
        {
            return KaevoProfileJellyfinBindingReassignmentResult.OwnerAmbiguous;
        }

        var actualSourceProfileId = owners.SingleOrDefault();
        var normalizedExpectedSourceProfileId = string.IsNullOrWhiteSpace(expectedSourceProfileId)
            ? null
            : expectedSourceProfileId;
        if (bindings.TryGetValue(targetProfileId!, out var alreadyBoundUserId)
            && string.Equals(alreadyBoundUserId, normalizedUserId, StringComparison.Ordinal)
            && string.Equals(actualSourceProfileId, targetProfileId, StringComparison.Ordinal))
        {
            // A duplicated connector delivery arrives after the first CAS move:
            // the only owner is now the requested target. Preserve every other
            // binding and report the durable idempotent outcome.
            return KaevoProfileJellyfinBindingReassignmentResult.AlreadyBound;
        }
        if (!string.Equals(
                actualSourceProfileId,
                normalizedExpectedSourceProfileId,
                StringComparison.Ordinal))
        {
            return KaevoProfileJellyfinBindingReassignmentResult.OwnerMismatch;
        }

        if (bindings.TryGetValue(targetProfileId!, out var targetUserId))
        {
            if (!string.Equals(targetUserId, normalizedUserId, StringComparison.Ordinal))
            {
                return KaevoProfileJellyfinBindingReassignmentResult.TargetAlreadyBound;
            }
            return KaevoProfileJellyfinBindingReassignmentResult.AlreadyBound;
        }

        if (actualSourceProfileId is null && bindings.Count >= MaximumBindings)
        {
            return KaevoProfileJellyfinBindingReassignmentResult.BindingCapacityReached;
        }

        if (actualSourceProfileId is not null)
        {
            bindings.Remove(actualSourceProfileId);
        }
        bindings[targetProfileId!] = normalizedUserId;
        updatedBindingsJson = Serialize(bindings);
        return KaevoProfileJellyfinBindingReassignmentResult.Reassigned;
    }

    internal static bool TryUnbind(
        string? bindingsJson,
        string? cloudProfileId,
        string? jellyfinUserId,
        out string updatedBindingsJson)
    {
        updatedBindingsJson = bindingsJson ?? string.Empty;
        if (!ValidProfileId(cloudProfileId)
            || !TryNormalizeJellyfinUserId(jellyfinUserId, out var normalizedUserId)
            || string.IsNullOrWhiteSpace(bindingsJson)
            || !TryRead(bindingsJson, out var bindings))
        {
            return false;
        }

        if (!bindings.TryGetValue(cloudProfileId!, out var existingUserId))
        {
            // Exact absence is idempotent only when the same Jellyfin identity
            // is not bound to a different profile.
            return !bindings.Any(entry =>
                string.Equals(entry.Value, normalizedUserId, StringComparison.Ordinal));
        }

        if (!string.Equals(existingUserId, normalizedUserId, StringComparison.Ordinal))
        {
            return false;
        }

        bindings.Remove(cloudProfileId!);
        updatedBindingsJson = JsonSerializer.Serialize(
            bindings.OrderBy(entry => entry.Key, StringComparer.Ordinal)
                .ToDictionary(entry => entry.Key, entry => entry.Value, StringComparer.Ordinal));
        return true;
    }

    internal static bool TryNormalizeJellyfinUserId(string? value, out string normalized)
    {
        normalized = string.Empty;
        if (string.IsNullOrWhiteSpace(value)
            || value.Length > 64
            || !Guid.TryParse(value, out var parsed)
            || parsed == Guid.Empty)
        {
            return false;
        }

        normalized = parsed.ToString("N");
        return true;
    }

    /// <summary>
    /// Resolves a member capability only from the durable binding map.  The
    /// older single-owner compatibility fields are intentionally excluded: a
    /// username-auth member must never inherit the connector owner's identity.
    /// </summary>
    internal static bool TryResolveMemberCapabilityBinding(
        string? bindingsJson,
        string? cloudProfileId,
        string? bindingHandle,
        string? bindingRevision,
        out string jellyfinUserId)
    {
        jellyfinUserId = string.Empty;
        if (!ValidProfileId(cloudProfileId)
            || string.IsNullOrWhiteSpace(bindingHandle)
            || string.IsNullOrWhiteSpace(bindingRevision)
            || string.IsNullOrWhiteSpace(bindingsJson)
            || !TryRead(bindingsJson, out var bindings)
            || !bindings.TryGetValue(cloudProfileId!, out var mappedUserId)
            || !TryNormalizeJellyfinUserId(mappedUserId, out var normalizedUserId))
        {
            return false;
        }

        var expectedHandle = MemberBindingHandle(cloudProfileId!, normalizedUserId);
        var expectedRevision = MemberBindingRevision(cloudProfileId!, normalizedUserId);
        if (!FixedEquals(bindingHandle, expectedHandle)
            || !FixedEquals(bindingRevision, expectedRevision))
        {
            return false;
        }

        jellyfinUserId = normalizedUserId;
        return true;
    }

    internal static string OpaqueHandle(string domain, string value)
    {
        if (string.IsNullOrWhiteSpace(domain) || string.IsNullOrWhiteSpace(value)
            || domain.Any(char.IsWhiteSpace) || domain.Any(char.IsControl)
            || value.Any(char.IsControl))
        {
            throw new InvalidOperationException("memberMediaCapabilityInvalid");
        }
        return "sha256:" + Base64Url(SHA256.HashData(Encoding.UTF8.GetBytes(
            "kaevo-member-media-v1/" + domain + "\0" + value)));
    }

    internal static string MemberBindingRevision(string cloudProfileId, string jellyfinUserId)
    {
        if (!ValidProfileId(cloudProfileId)
            || !TryNormalizeJellyfinUserId(jellyfinUserId, out var normalizedUserId))
        {
            throw new InvalidOperationException("memberMediaCapabilityInvalid");
        }
        return "sha256:" + Base64Url(SHA256.HashData(Encoding.UTF8.GetBytes(
            "kaevo-member-media-v1/binding-revision\0" + cloudProfileId + "\0" + normalizedUserId)));
    }

    internal static string MemberBindingHandle(string cloudProfileId, string jellyfinUserId)
    {
        if (!ValidProfileId(cloudProfileId)
            || !TryNormalizeJellyfinUserId(jellyfinUserId, out var normalizedUserId))
        {
            throw new InvalidOperationException("memberMediaCapabilityInvalid");
        }
        return "sha256:" + Base64Url(SHA256.HashData(Encoding.UTF8.GetBytes(
            "kaevo-member-media-v1/binding\0" + cloudProfileId + "\0" + normalizedUserId)));
    }

    internal static bool ValidMemberCapabilityContext(KaevoMemberMediaCapabilityContext context) =>
        context is not null
        && ValidProfileId(context.ProfileId)
        && !string.IsNullOrWhiteSpace(context.ConnectorId)
        && context.ConnectorId.Length <= 256
        && context.RequiredScopes is { Count: > 0 }
        && ValidOpaqueHandle(context.PrincipalHandle)
        && ValidOpaqueHandle(context.HouseholdHandle)
        && ValidOpaqueHandle(context.DeviceInstallationHandle);

    private static bool ValidProfileId(string? value) =>
        !string.IsNullOrWhiteSpace(value)
        && value.Length <= 256
        && !value.Any(char.IsWhiteSpace)
        && !value.Any(char.IsControl);

    private static bool ValidOpaqueHandle(string? value) =>
        value is { Length: 50 }
        && value.StartsWith("sha256:", StringComparison.Ordinal)
        && value[7..].All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_');

    private static bool FixedEquals(string actual, string expected) =>
        actual.Length == expected.Length
        && CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(actual), Encoding.ASCII.GetBytes(expected));

    private static string Base64Url(byte[] value) => Convert.ToBase64String(value)
        .TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static bool TryRead(string json, out Dictionary<string, string> bindings)
    {
        bindings = new Dictionary<string, string>(StringComparer.Ordinal);
        try
        {
            var decoded = JsonSerializer.Deserialize<Dictionary<string, string>>(json);
            if (decoded is null
                || decoded.Count > MaximumBindings
                || decoded.Any(entry => !ValidProfileId(entry.Key)
                    || !TryNormalizeJellyfinUserId(entry.Value, out _)))
            {
                return false;
            }

            bindings = new Dictionary<string, string>(decoded, StringComparer.Ordinal);
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static bool TryReadOrEmpty(string? json, out Dictionary<string, string> bindings)
    {
        bindings = new Dictionary<string, string>(StringComparer.Ordinal);
        return string.IsNullOrWhiteSpace(json) || TryRead(json, out bindings);
    }

    private static string BindingRevision(string? value) =>
        "sha256:" + Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(value ?? string.Empty)))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static string OperationFingerprint(string operationId) => BindingRevision(operationId);

    private static bool TryReadClaimOperations(string? json, out Dictionary<string, string> operations)
    {
        operations = new Dictionary<string, string>(StringComparer.Ordinal);
        if (string.IsNullOrWhiteSpace(json))
        {
            return true;
        }
        try
        {
            var decoded = JsonSerializer.Deserialize<Dictionary<string, string>>(json);
            if (decoded is null || decoded.Count > MaximumBindings
                || decoded.Any(entry => !ValidProfileId(entry.Key)
                    || !entry.Value.StartsWith("sha256:", StringComparison.Ordinal)
                    || entry.Value.Length != 50))
            {
                return false;
            }
            operations = new Dictionary<string, string>(decoded, StringComparer.Ordinal);
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static string SerializeClaimOperations(Dictionary<string, string> operations) =>
        JsonSerializer.Serialize(operations.OrderBy(entry => entry.Key, StringComparer.Ordinal)
            .ToDictionary(entry => entry.Key, entry => entry.Value, StringComparer.Ordinal));

    private static string Serialize(Dictionary<string, string> bindings) =>
        JsonSerializer.Serialize(
            bindings.OrderBy(entry => entry.Key, StringComparer.Ordinal)
                .ToDictionary(entry => entry.Key, entry => entry.Value, StringComparer.Ordinal));
}
