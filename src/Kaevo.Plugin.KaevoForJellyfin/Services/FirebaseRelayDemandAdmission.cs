using System.Runtime.CompilerServices;
using System.Text.Json;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

internal sealed record FirebaseRelayDemandRecovery(IReadOnlyList<string> DemandIds)
{
    public override string ToString() => "Firebase relay demand recovery (redacted)";
    internal static FirebaseRelayDemandRecovery Parse(JsonElement body, FirebaseControlAdmission admission)
    {
        try
        {
            admission.Check();
            FirebaseControlTokenExchange.UniqueObject(body);
            var expected = new HashSet<string>(["state", "connection_id", "epoch", "activation_allowed",
                "demand_ids", "page_full", "retry_after_seconds"]);
            var state = body.GetProperty("state").GetString();
            if (!expected.SetEquals(body.EnumerateObject().Select(p => p.Name))
                || state is not ("recovered" or "throttled")
                || body.GetProperty("connection_id").GetString() != admission.Channel
                || body.GetProperty("epoch").GetString() != admission.Epoch
                || body.GetProperty("activation_allowed").ValueKind != JsonValueKind.True
                || body.GetProperty("page_full").ValueKind is not (JsonValueKind.False or JsonValueKind.True)
                || body.GetProperty("retry_after_seconds").GetInt32() is < 1 or > 75)
                throw new InvalidOperationException();
            var ids = body.GetProperty("demand_ids").EnumerateArray().Select(v => v.GetString()!).ToArray();
            if (ids.Length > 8 || ids.Any(id => !FirebaseRelayDemandAdmission.IsDemandId(id))
                || ids.Distinct(StringComparer.Ordinal).Count() != ids.Length
                || (state == "throttled" && body.GetProperty("page_full").GetBoolean())
                || (state == "recovered" && (body.GetProperty("retry_after_seconds").GetInt32() < 60
                    || body.GetProperty("page_full").GetBoolean() != (ids.Length == 8))))
                throw new InvalidOperationException();
            return new(ids);
        }
        catch (Exception) { throw new InvalidOperationException("firebaseRelayDemandRecoveryInvalid"); }
    }
}

// The input must be the HTTPS response to our freshly signed exact-ID request.
// JSON decoding alone is not signature verification. Neither the notification
// nor this transport receipt authorizes any provider request or playback bytes.
internal static class FirebaseRelayDemandAdmission
{
    internal const string Prefix = "relay-demand:";

    internal static bool IsDemandId(string? id) => id is not null
        && Guid.TryParseExact(id, "D", out var guid) && guid.ToString("D") == id;

    internal static bool IsAdmissionOperation(string operation)
    {
        var parts = operation.Split('/');
        return parts.Length == 3 && parts[0] == "relay-demands"
            && IsDemandId(parts[1]) && parts[2] == "admit";
    }

    internal static FirebaseRelayDemand Parse(JsonElement body, string connectorId,
        string demandId, FirebaseControlAdmission admission, DateTimeOffset? now = null)
    {
        try
        {
            var current = now ?? DateTimeOffset.UtcNow;
            FirebaseControlTokenExchange.UniqueObject(body);
            var expected = new HashSet<string>(["state", "connector_id", "demand_id",
                "connection_id", "epoch", "issued_at", "expires_at", "activation_allowed"]);
            if (!IsDemandId(demandId) || !expected.SetEquals(body.EnumerateObject().Select(p => p.Name))
                || body.GetProperty("state").GetString() != "admitted"
                || body.GetProperty("connector_id").GetString() != connectorId
                || body.GetProperty("demand_id").GetString() != demandId
                || body.GetProperty("connection_id").GetString() != admission.Channel
                || body.GetProperty("epoch").GetString() != admission.Epoch
                || body.GetProperty("activation_allowed").ValueKind != JsonValueKind.True
                || admission.ExpiresAt <= current
                || !FirebaseFirestoreControlListener.IsOpaque(admission.Channel, 43)
                || !FirebaseFirestoreControlListener.IsOpaque(admission.Epoch, 32))
                throw new InvalidOperationException();
            var issued = DateTimeOffset.FromUnixTimeSeconds(body.GetProperty("issued_at").GetInt64());
            var expires = DateTimeOffset.FromUnixTimeSeconds(body.GetProperty("expires_at").GetInt64());
            if (issued <= DateTimeOffset.UnixEpoch || issued > current || expires <= current
                || expires <= issued || expires - issued > TimeSpan.FromSeconds(120))
                throw new InvalidOperationException();
            return new(demandId, issued, expires);
        }
        catch (Exception) { throw new InvalidOperationException("firebaseRelayDemandAdmissionInvalid"); }
    }

    // A single bounded retry reconciles a lost response with a fresh signature.
    // Denial never falls through to provider command execution, and a failed
    // hint does not cancel work the retained dispatcher has already claimed.
    internal static async IAsyncEnumerable<string> FilterAsync(
        IAsyncEnumerable<string> hints,
        Func<string, CancellationToken, Task<FirebaseRelayDemand>> admit,
        Func<FirebaseRelayDemand, CancellationToken, ValueTask> deliver,
        Action<string> evidence,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await foreach (var hint in hints.WithCancellation(cancellationToken).ConfigureAwait(false))
        {
            if (hint is null || !hint.StartsWith(Prefix, StringComparison.Ordinal))
            {
                yield return hint!;
                continue;
            }
            var id = hint[Prefix.Length..];
            if (!IsDemandId(id)) { Emit(evidence, "demand_hint_rejected"); continue; }
            FirebaseRelayDemand? demand = null;
            for (var attempt = 0; attempt < 2; attempt++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    demand = await admit(id, cancellationToken).ConfigureAwait(false);
                    if (demand.Id != id) throw new InvalidOperationException();
                    break;
                }
                catch (Exception)
                {
                    demand = null;
                    cancellationToken.ThrowIfCancellationRequested();
                    Emit(evidence, "demand_admission_deferred");
                }
            }
            if (demand is not null)
            {
                // Sink/cancellation failures belong to the runtime owner. Do not
                // hide them as authentication failures or replay an admitted sink.
                await deliver(demand, cancellationToken).ConfigureAwait(false);
                Emit(evidence, "demand_admitted");
            }
        }
    }

    private static void Emit(Action<string> sink, string category)
    {
        try { sink(category); } catch (Exception) { /* Best-effort redacted evidence. */ }
    }
}
