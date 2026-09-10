using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Kaevo.Plugin.KaevoForJellyfin.Configuration;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

internal sealed record KaevoFirebaseMigrationJournal(
    string TransitionId, KaevoPairingV3Connector Before, KaevoPairingV3Connector After,
    string BeforeCloudUrl, string BeforeProfileId, string BeforeBindingsJson, string BeforeJellyfinUserId,
    string ProfileId, string BindingsJson, string JellyfinUserId, long ExpiresAt);

public sealed partial class KaevoPairingV3Service
{
    private readonly SemaphoreSlim _firebaseMigrationGate = new(1, 1);

    internal async Task MigrateFirebaseAsync(PluginConfiguration configuration, Func<bool> paused,
        Action save, Func<string, bool> userExists, CancellationToken cancellationToken)
    {
        await _firebaseMigrationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            void Guard()
            {
                if (configuration.CloudConnectorEnabled || !paused())
                    throw new InvalidOperationException("firebaseMigrationPauseRequired");
            }
            Guard();
            var context = await _store.ReadAsync(s => (s.Connector, s.Identity, s.FirebaseMigration), cancellationToken).ConfigureAwait(false);
            if (context.Connector is null || context.Identity is null || context.Connector.Status != "active"
                || context.Connector.ProtocolVersion != KaevoPairingV3Crypto.Protocol)
                throw new InvalidOperationException("firebaseMigrationPairingRequired");
            var journal = context.FirebaseMigration;
            if (journal is null)
            {
                if (configuration.ConnectorId != context.Connector.ConnectorId)
                    throw new InvalidOperationException("firebaseMigrationConfigurationChanged");
                var oldUrl = configuration.CloudBaseUrl;
                var oldProfile = configuration.ProfileId;
                var oldBindings = configuration.ProfileJellyfinBindingsJson;
                var oldUser = configuration.JellyfinUserId;
                if (!Regex.IsMatch(context.Connector.ConnectorId, "^[A-Za-z0-9._:-]{1,128}$"))
                    throw new InvalidOperationException("firebaseMigrationInvalid");
                var body = new { connector_id = context.Connector.ConnectorId, migration_only = true };
                var route = "/v3/home-connectors/" + context.Connector.ConnectorId + "/heartbeat";
                var proof = await PrepareConnectorRequestAsync("POST", route, body, cancellationToken).ConfigureAwait(false);
                var uri = new Uri(KaevoFirebaseRuntime.Endpoint + route);
                using var message = new HttpRequestMessage(HttpMethod.Post, uri)
                { Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json") };
                message.Headers.TryAddWithoutValidation("X-Kaevo-Plugin-Key-Id", proof.PluginKeyId);
                message.Headers.TryAddWithoutValidation("X-Kaevo-Plugin-Timestamp", proof.Timestamp);
                message.Headers.TryAddWithoutValidation("X-Kaevo-Plugin-Nonce", proof.Nonce);
                message.Headers.TryAddWithoutValidation("X-Kaevo-Plugin-Signature", proof.Signature);
                message.Headers.TryAddWithoutValidation("X-Kaevo-Plugin-Signature-Version", "1");
                using var response = await _connectorHttp.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
                if (response.StatusCode != System.Net.HttpStatusCode.OK || response.RequestMessage?.RequestUri != uri
                    || response.Content.Headers.ContentLength > 65536
                    || response.Content.Headers.ContentType?.MediaType != "application/json")
                    throw new InvalidOperationException("firebaseMigrationUnavailable");
                await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
                using var bytes = new MemoryStream(); var buffer = new byte[4096]; int count;
                while ((count = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) != 0)
                {
                    if (bytes.Length + count > 65536) throw new InvalidOperationException("firebaseMigrationUnavailable");
                    bytes.Write(buffer, 0, count);
                }
                using var document = JsonDocument.Parse(bytes.ToArray());
                journal = ValidateFirebaseMigration(document.RootElement, context.Connector, oldUrl, oldProfile, oldBindings, oldUser, userExists);
                Guard();
                if (configuration.CloudBaseUrl != oldUrl || configuration.ProfileId != oldProfile || configuration.JellyfinUserId != oldUser
                    || configuration.ProfileJellyfinBindingsJson != oldBindings || configuration.ConnectorId != context.Connector.ConnectorId)
                    throw new InvalidOperationException("firebaseMigrationConfigurationChanged");
                await _store.MutateAsync(s =>
                {
                    if (s.Connector != context.Connector || s.Identity != context.Identity || s.FirebaseMigration is not null)
                        throw new InvalidOperationException("firebaseMigrationPairingChanged");
                    s.FirebaseMigration = journal; return true;
                }, cancellationToken).ConfigureAwait(false);
            }
            Guard();
            if (configuration.ConnectorId != journal.Before.ConnectorId && configuration.ConnectorId != journal.After.ConnectorId)
                throw new InvalidOperationException("firebaseMigrationConfigurationChanged");
            if (configuration.CloudBaseUrl != journal.BeforeCloudUrl && configuration.CloudBaseUrl != KaevoFirebaseRuntime.Endpoint)
                throw new InvalidOperationException("firebaseMigrationConfigurationChanged");
            if (configuration.ProfileJellyfinBindingsJson != journal.BeforeBindingsJson && configuration.ProfileJellyfinBindingsJson != journal.BindingsJson)
                throw new InvalidOperationException("firebaseMigrationConfigurationChanged");
            if ((configuration.ProfileId != journal.BeforeProfileId && configuration.ProfileId != journal.ProfileId)
                || (configuration.JellyfinUserId != journal.BeforeJellyfinUserId && configuration.JellyfinUserId != journal.JellyfinUserId))
                throw new InvalidOperationException("firebaseMigrationConfigurationChanged");
            await _store.MutateAsync(s =>
            {
                if (s.FirebaseMigration != journal || (s.Connector != journal.Before && s.Connector != journal.After)
                    || s.Identity?.Fingerprint != journal.After.PluginFingerprint)
                    throw new InvalidOperationException("firebaseMigrationPairingChanged");
                if (s.Connector == journal.Before && DateTimeOffset.UtcNow.ToUnixTimeSeconds() >= journal.ExpiresAt)
                    throw new InvalidOperationException("firebaseMigrationExpired");
                s.Connector = journal.After; return true;
            }, cancellationToken).ConfigureAwait(false);
            // A crash between these two stores is recoverable from the journal.
            // The connection stays paused throughout and no feature flags or
            // local provider secrets are reset by this operation.
            Guard();
            var previous = (configuration.CloudBaseUrl, configuration.CloudEnvironment, configuration.ConnectorId,
                configuration.ProfileId, configuration.ProfileJellyfinBindingsJson, configuration.JellyfinUserId);
            configuration.CloudBaseUrl = KaevoFirebaseRuntime.Endpoint;
            configuration.CloudEnvironment = "development";
            configuration.ConnectorId = journal.After.ConnectorId;
            configuration.ProfileId = journal.ProfileId;
            configuration.ProfileJellyfinBindingsJson = journal.BindingsJson;
            configuration.JellyfinUserId = journal.JellyfinUserId;
            try { save(); }
            catch
            {
                // Do not report an in-memory selection as a durable switch.
                (configuration.CloudBaseUrl, configuration.CloudEnvironment, configuration.ConnectorId,
                    configuration.ProfileId, configuration.ProfileJellyfinBindingsJson, configuration.JellyfinUserId) = previous;
                throw;
            }
        }
        finally { _firebaseMigrationGate.Release(); }
    }

    internal static KaevoFirebaseMigrationJournal ValidateFirebaseMigration(JsonElement root,
        KaevoPairingV3Connector old, string oldUrl, string oldProfile, string oldBindings, string oldUser, Func<string, bool> userExists)
    {
        FirebaseControlTokenExchange.UniqueObject(root);
        string Text(JsonElement item, string name)
        {
            var value = item.GetProperty(name).GetString();
            if (value is null || !Regex.IsMatch(value, "^[A-Za-z0-9._:-]{1,128}$"))
                throw new InvalidOperationException("firebaseMigrationInvalid");
            return value;
        }
        if (root.EnumerateObject().Count() != 9 || Text(root, "state") != "connector_migration_prepared"
            || Text(root, "project_id") != FirebaseFirestoreControlListener.DevelopmentProject
            || Text(root, "old_connector_id") != old.ConnectorId || root.GetProperty("activation_allowed").ValueKind != JsonValueKind.False)
            throw new InvalidOperationException("firebaseMigrationInvalid");
        var transition = Text(root, "transition_id"); var expires = root.GetProperty("expires_at").GetInt64();
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (!Regex.IsMatch(transition, "^[a-f0-9]{64}$") || expires <= now || expires > now + 86400)
            throw new InvalidOperationException("firebaseMigrationInvalid");
        var binding = root.GetProperty("binding"); FirebaseControlTokenExchange.UniqueObject(binding);
        if (binding.EnumerateObject().Count() != 10 || Text(binding, "connector_id") == old.ConnectorId
            || Text(binding, "plugin_instance_id") != old.PluginInstanceId
            || Text(binding, "plugin_key_id") != old.KeyVersion.ToString(System.Globalization.CultureInfo.InvariantCulture)
            || Text(binding, "plugin_public_key_fingerprint") != old.PluginFingerprint
            || Text(binding, "jellyfin_server_id") != old.JellyfinServerId)
            throw new InvalidOperationException("firebaseMigrationInvalid");
        _ = Text(binding, "account_id"); _ = Text(binding, "household_id");
        var profile = Text(binding, "profile_id"); var user = Text(root, "jellyfin_user_id");
        if (!string.Equals(oldUser, user, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("firebaseMigrationUserChanged");
        var maps = root.GetProperty("profile_bindings"); FirebaseControlTokenExchange.UniqueObject(maps);
        if (maps.EnumerateObject().Count() is < 1 or > 100 || maps.GetProperty(profile).GetString() != user)
            throw new InvalidOperationException("firebaseMigrationInvalid");
        var values = new SortedDictionary<string, string>(StringComparer.Ordinal);
        foreach (var entry in maps.EnumerateObject())
        {
            var id = Text(maps, entry.Name);
            if (!Regex.IsMatch(entry.Name, "^[A-Za-z0-9._:-]{1,128}$") || !Regex.IsMatch(id, "^[a-fA-F0-9]{32}$") || !userExists(id))
                throw new InvalidOperationException("firebaseMigrationUserChanged");
            values.Add(entry.Name, id);
        }
        var replacement = old with { ConnectorId = Text(binding, "connector_id"), AccountBinding = Text(binding, "account_binding"),
            FamilyBinding = Text(binding, "family_binding"), LastContactState = "firebase_migrated_paused" };
        return new(transition, old, replacement, oldUrl, oldProfile, oldBindings, oldUser, profile, JsonSerializer.Serialize(values), user, expires);
    }
}
