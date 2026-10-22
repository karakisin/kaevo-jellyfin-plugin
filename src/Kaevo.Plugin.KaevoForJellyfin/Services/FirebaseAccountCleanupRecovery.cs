using System.Text.Json;
using System.Text.RegularExpressions;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

// This receipt grants no Firebase sign-in, listener, relay or playback access.
// Request IDs are hints; each command still needs a fresh signed exact claim
// and the retained local provider-identity/deletion-policy checks.
internal sealed record FirebaseAccountCleanupRecovery(
    string ConnectorId, string OperationId, string PlanDigest, IReadOnlyList<string> RequestIds,
    DateTimeOffset ExpiresAt, int RetryAfterSeconds)
{
    internal const string Capability = "account_lifecycle_cleanup_delivery_v1";
    internal const string Transport = "signed-account-cleanup-v1";
    public override string ToString() => "Firebase account cleanup (redacted)";

    internal static async Task RunSessionAsync(Func<Task> normalSession, Func<Task> cleanup,
        CancellationToken cancellationToken)
    {
        try { await normalSession().ConfigureAwait(false); }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            // The normal owner has finished draining before cleanup starts.
            // No concurrent provider worker or fallback to an AWS transport.
            await cleanup().ConfigureAwait(false);
        }
    }

    internal static FirebaseAccountCleanupRecovery Parse(JsonElement body, string connectorId, DateTimeOffset now)
    {
        try
        {
            FirebaseControlTokenExchange.UniqueObject(body);
            var fields = new HashSet<string>(["state", "connector_control_protocol", "connector_control_transport",
                "project_id", "connector_id", "operation_id", "plan_digest", "request_ids", "expires_at",
                "retry_after_seconds", "cleanup_authorized", "activation_allowed"]);
            if (!fields.SetEquals(body.EnumerateObject().Select(p => p.Name))
                || body.GetProperty("state").GetString() != "account_cleanup"
                || body.GetProperty("connector_control_protocol").GetInt32() != 2
                || body.GetProperty("connector_control_transport").GetString() != Transport
                || body.GetProperty("project_id").GetString() != FirebaseFirestoreControlListener.DevelopmentProject
                || body.GetProperty("connector_id").GetString() != connectorId
                || !body.GetProperty("cleanup_authorized").GetBoolean()
                || body.GetProperty("activation_allowed").GetBoolean()) throw new InvalidOperationException();
            var operation = body.GetProperty("operation_id").GetString()!;
            var plan = body.GetProperty("plan_digest").GetString()!;
            if (!Regex.IsMatch(operation, "\\Aald2_[A-Za-z0-9_-]{24,96}\\z")
                || !Regex.IsMatch(plan, "\\Aalfp1_[a-f0-9]{64}\\z")) throw new InvalidOperationException();
            var expires = DateTimeOffset.FromUnixTimeSeconds(body.GetProperty("expires_at").GetInt64());
            var retry = body.GetProperty("retry_after_seconds").GetInt32();
            var ids = body.GetProperty("request_ids").EnumerateArray().Select(p => p.GetString()!).ToArray();
            if (expires <= now || expires > now.AddSeconds(30) || retry is < 1 or > 15
                || ids.Length > 32 || ids.Any(id => id is null || !Guid.TryParseExact(id, "D", out _)
                    || id != id.ToLowerInvariant())
                || ids.Distinct(StringComparer.Ordinal).Count() != ids.Length) throw new InvalidOperationException();
            return new(connectorId, operation, plan, Array.AsReadOnly(ids), expires, retry);
        }
        catch (Exception) { throw new InvalidOperationException("firebaseAccountCleanupInvalid"); }
    }

    internal void RequireClaim(CloudRequest request)
    {
        if (!RequestIds.Contains(request.RequestId, StringComparer.Ordinal)
            || request.Method != "COMMAND" || request.Provider != "home_server"
            || request.Operation is not (KaevoCloudConnectorService.LifecycleV2SeerrDelete
                or KaevoCloudConnectorService.LifecycleV2SeerrVerify
                or KaevoCloudConnectorService.LifecycleV2JellyfinDelete
                or KaevoCloudConnectorService.LifecycleV2JellyfinVerify)
            || request.Path != "/commands/" + request.Operation
            || request.ProfileProviderBinding?.ConnectorId != ConnectorId
            || request.Parameters is null || !request.Parameters.TryGetValue("operation_id", out var op)
            || op.ValueKind != JsonValueKind.String || op.GetString() != OperationId)
            throw new InvalidOperationException("firebaseAccountCleanupClaimMismatch");
    }

    internal static async Task RunBatchAsync(FirebaseAccountCleanupRecovery receipt,
        Func<string, CancellationToken, Task<CloudRequest?>> claim,
        Func<CloudRequest, CancellationToken, Task> handle, CancellationToken cancellationToken,
        TimeProvider? clock = null, Func<TimeSpan, CancellationToken, Task>? delay = null)
    {
        clock ??= TimeProvider.System;
        delay ??= (duration, token) => Task.Delay(duration, clock, token);
        // A server checkpoint also bounds repeats across plugin restarts. Keep
        // the client's delay even when a command fails, and never cancel an
        // already-claimed operation merely because this hint receipt expires.
        try
        {
            foreach (var id in receipt.RequestIds)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (clock.GetUtcNow() >= receipt.ExpiresAt) break;
                var request = await claim(id, cancellationToken).ConfigureAwait(false);
                if (request is null) continue;
                receipt.RequireClaim(request);
                await handle(request, cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            await delay(TimeSpan.FromSeconds(receipt.RetryAfterSeconds), cancellationToken).ConfigureAwait(false);
        }
    }
}
