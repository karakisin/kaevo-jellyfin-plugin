using System.Text.Json;
using Kaevo.Plugin.KaevoForJellyfin.Configuration;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

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
        string? jellyfinUserId)
    {
        if (!TryBind(
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

    internal static bool TryBind(
        string? bindingsJson,
        string? cloudProfileId,
        string? jellyfinUserId,
        out string updatedBindingsJson)
    {
        updatedBindingsJson = bindingsJson ?? string.Empty;
        if (!ValidProfileId(cloudProfileId)
            || !TryNormalizeJellyfinUserId(jellyfinUserId, out var normalizedUserId))
        {
            return false;
        }

        Dictionary<string, string> bindings;
        if (string.IsNullOrWhiteSpace(bindingsJson))
        {
            bindings = new Dictionary<string, string>(StringComparer.Ordinal);
        }
        else if (!TryRead(bindingsJson, out bindings))
        {
            return false;
        }

        if (!bindings.ContainsKey(cloudProfileId!) && bindings.Count >= MaximumBindings)
        {
            return false;
        }

        bindings[cloudProfileId!] = normalizedUserId;
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
