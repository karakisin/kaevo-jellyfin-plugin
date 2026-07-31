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

    private static bool ValidProfileId(string? value) =>
        !string.IsNullOrWhiteSpace(value)
        && value.Length <= 256
        && !value.Any(char.IsWhiteSpace)
        && !value.Any(char.IsControl);

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
}
