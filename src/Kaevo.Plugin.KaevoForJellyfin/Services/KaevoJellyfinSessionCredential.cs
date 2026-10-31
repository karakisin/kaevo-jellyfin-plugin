using System.Runtime.CompilerServices;
using Kaevo.Plugin.KaevoForJellyfin.Configuration;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

// A replacement is published only after the existing same-server verification
// and atomic secret-store save succeed. Never discover, mint or repair keys here.
internal sealed class KaevoJellyfinSessionCredential
{
    internal sealed record Scope(string Connector, string Root, string User)
    {
        internal static Scope From(PluginConfiguration configuration) => new(
            configuration.ConnectorId, configuration.LocalJellyfinBaseUrl.TrimEnd('/'), configuration.JellyfinUserId);
    }
    private sealed record Replacement(Scope Scope, string Key);
    private readonly ConditionalWeakTable<KaevoConnectorSecrets, Replacement> replacements = new();
    private readonly object gate = new();

    internal string Read(PluginConfiguration configuration, KaevoConnectorSecrets session, bool explicitlyConfigured)
    {
        if (explicitlyConfigured) return session.JellyfinApiKey;
        lock (gate)
            return replacements.TryGetValue(session, out var value) && value.Scope == Scope.From(configuration)
                ? value.Key : session.JellyfinApiKey;
    }

    internal void PublishSaved(Scope verifiedScope, KaevoConnectorSecrets session, string key)
    {
        if (string.IsNullOrWhiteSpace(key) || key.Any(c => char.IsControl(c) || char.IsWhiteSpace(c) || c is '"' or '\\'))
            throw new InvalidOperationException("jellyfinApiKeyInvalid");
        lock (gate)
        {
            replacements.Remove(session);
            replacements.Add(session, new(verifiedScope, key));
        }
    }
}
