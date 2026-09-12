using System.Text;
using System.Text.Json;
using Google.Api.Gax.Grpc;
using Google.Cloud.Firestore.V1;
using Timestamp = Google.Protobuf.WellKnownTypes.Timestamp;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

// Commands come only from a server-owned, exact-document TLS listener whose
// Firebase token and current lease have already been verified. They are NOT
// inferred from notification IDs or caller configuration. Results remain signed
// and are validated by Cloud before any media grant can be issued.
internal sealed class FirebasePlaybackMailbox(FirestoreClient client, KaevoPairingV3Service pairing,
    string project = FirebaseFirestoreControlListener.DevelopmentProject)
{
    internal const string Capability = "firebase_playback_mailbox_v1";
    private readonly object sync = new();
    private readonly Dictionary<string, Delivery> commands = new(StringComparer.Ordinal);
    private readonly Dictionary<string, long> consumed = new(StringComparer.Ordinal);

    internal sealed record Delivery(CloudRequest Request, string Channel, string Epoch,
        string IdToken, DateTimeOffset LeaseExpiry, long ExpiresAt)
    { public override string ToString() => "Firebase playback delivery (private)"; }

    internal void Accept(Document document, FirebaseControlAdmission admission, string token)
    {
        admission.Check();
        var parsed = Parse(document, admission.Channel, admission.Epoch);
        lock (sync)
        {
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            foreach (var key in consumed.Where(pair => pair.Value <= now).Select(pair => pair.Key).ToArray())
                consumed.Remove(key);
            foreach (var key in commands.Where(pair => pair.Value.ExpiresAt <= now
                         || pair.Value.Channel != admission.Channel || !parsed.ContainsKey(pair.Key))
                         .Select(pair => pair.Key).ToArray()) commands.Remove(key);
            foreach (var (id, value) in parsed)
                if (value.ExpiresAt > now && !consumed.ContainsKey(id))
                    commands[id] = new(value.Request, admission.Channel, admission.Epoch, token,
                        admission.ExpiresAt, value.ExpiresAt);
        }
    }

    // A fresh lease cannot revive an old admitted command. A reconnect or a
    // duplicate snapshot in this owner cannot execute it a second time.
    internal Delivery? Take(string requestId)
    {
        lock (sync)
        {
            if (!commands.Remove(requestId, out var value)) return null;
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (value.ExpiresAt <= now || value.LeaseExpiry <= DateTimeOffset.UtcNow) return null;
            consumed[requestId] = value.ExpiresAt;
            return value;
        }
    }

    internal static Dictionary<string, (CloudRequest Request, long ExpiresAt)> Parse(
        Document document, string channel, string epoch)
    {
        var result = new Dictionary<string, (CloudRequest, long)>(StringComparer.Ordinal);
        if (!document.Fields.TryGetValue("playback_commands", out var commands)) return result;
        if (commands.ValueTypeCase != Value.ValueTypeOneofCase.MapValue || commands.MapValue.Fields.Count > 4)
            throw Invalid();
        var ids = document.Fields["request_ids"].ArrayValue.Values.Select(v => v.StringValue).ToHashSet(StringComparer.Ordinal);
        foreach (var (id, field) in commands.MapValue.Fields)
        {
            if (!ids.Contains(id) || !FirebaseFirestoreControlListener.IsRequestId(id)
                || field.ValueTypeCase != Value.ValueTypeOneofCase.StringValue
                || Encoding.UTF8.GetByteCount(field.StringValue) is < 1 or > 16384) throw Invalid();
            try
            {
                using var json = JsonDocument.Parse(field.StringValue, new JsonDocumentOptions { MaxDepth = 16 });
                var root = json.RootElement;
                var names = root.EnumerateObject().Select(p => p.Name).ToArray();
                if (names.Length != 5 || names.Distinct().Count() != 5
                    || !names.ToHashSet().SetEquals(new[] { "protocol", "channel", "epoch", "expires_at", "request" })
                    || root.GetProperty("protocol").GetInt32() != 1
                    || root.GetProperty("channel").GetString() != channel || root.GetProperty("epoch").GetString() != epoch)
                    throw Invalid();
                var rawRequest = root.GetProperty("request");
                var request = rawRequest.Deserialize<CloudRequest>();
                var expiry = root.GetProperty("expires_at").GetInt64();
                if (request is null || request.RequestId != id || request.Method != "COMMAND" || request.Provider != "home_server"
                    || request.Operation != "jellyfin.prepare_playback" || request.Path != "/commands/jellyfin.prepare_playback"
                    || request.Parameters is null || !request.Parameters.TryGetValue("origin_start_ticks", out var ticks)
                    || !ticks.TryGetInt64(out var start) || start < 0 || string.IsNullOrWhiteSpace(request.ProfileId)
                    || request.ProfileProviderBinding is not { Provider: "jellyfin" } binding
                    || string.IsNullOrWhiteSpace(binding.ConnectorId) || string.IsNullOrWhiteSpace(binding.ProviderUserId)
                    || rawRequest.GetProperty("connector_id").GetString() != binding.ConnectorId
                    || rawRequest.GetProperty("status").GetString() != "in_progress"
                    || request.OriginStartExpiresAt != expiry || expiry <= 0
                    || expiry > DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 30)
                    throw Invalid();
                result.Add(id, (request, expiry));
            }
            catch (Exception error) when (error is JsonException or InvalidOperationException or FormatException or KeyNotFoundException)
            { throw Invalid(); }
        }
        return result;
    }

    internal async Task<bool> DeliverAsync(Delivery delivery, string operation, object body,
        CancellationToken cancellationToken)
    {
        if (operation is not ("complete" or "fail")
            || project is not (FirebaseFirestoreControlListener.DevelopmentProject or FirebaseFirestoreControlListener.DemoProject)) throw Invalid();
        if (delivery.LeaseExpiry <= DateTimeOffset.UtcNow
            || delivery.ExpiresAt <= DateTimeOffset.UtcNow.ToUnixTimeSeconds()) return false;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(3));
        try
        {
            var values = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(
                JsonSerializer.Serialize(body, new JsonSerializerOptions(JsonSerializerDefaults.Web)))!;
            values["playback_mailbox_channel"] = JsonSerializer.SerializeToElement(delivery.Channel);
            values["playback_mailbox_epoch"] = JsonSerializer.SerializeToElement(delivery.Epoch);
            var signed = await pairing.PrepareFirebaseMailboxResultAsync(delivery.Request.RequestId,
                operation, values, deadline.Token).ConfigureAwait(false);
            if (signed.Body.Length > 131072) return false;
            var database = $"projects/{project}/databases/(default)";
            var path = database + "/documents/connector_signals/" + delivery.Channel
                + "/connector_playback_results/" + delivery.Request.RequestId;
            var document = new Document { Name = path, Fields =
            {
                ["epoch"] = new Value { StringValue = delivery.Epoch },
                ["operation"] = new Value { StringValue = operation },
                ["body_json"] = new Value { StringValue = Encoding.UTF8.GetString(signed.Body) },
                ["delete_after"] = new Value { TimestampValue = Timestamp.FromDateTimeOffset(DateTimeOffset.FromUnixTimeSeconds(delivery.ExpiresAt)) },
                ["headers"] = new Value { MapValue = new MapValue { Fields =
                    { signed.Headers.ToDictionary(p => p.Key, p => new Value { StringValue = p.Value }) } } },
            } };
            var write = new Write { Update = document, CurrentDocument = new Precondition { Exists = false },
                UpdateTransforms = { new DocumentTransform.Types.FieldTransform { FieldPath = "received_at",
                    SetToServerValue = DocumentTransform.Types.FieldTransform.Types.ServerValue.RequestTime } } };
            await client.CommitAsync(new CommitRequest { Database = database, Writes = { write } },
                CallSettings.FromCancellationToken(deadline.Token).WithHeader("authorization", "Bearer " + delivery.IdToken)
                    .WithHeader("google-cloud-resource-prefix", database)).ConfigureAwait(false);
            return true;
        }
        catch (Exception)
        {
            cancellationToken.ThrowIfCancellationRequested();
            // Retry only delivery through the existing signed HTTP callback;
            // never repeat ExecuteCommand or start another encoder.
            return false;
        }
    }

    private static InvalidOperationException Invalid() => new("firebasePlaybackMailboxInvalid");
}
