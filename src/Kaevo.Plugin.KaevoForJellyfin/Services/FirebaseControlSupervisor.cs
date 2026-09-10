using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text.Json;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

internal sealed record FirebaseControlRecovery(IReadOnlyList<string> RequestIds, bool More)
{
    public override string ToString() => "Firebase recovery hints (redacted)";

    internal static FirebaseControlRecovery Parse(JsonElement body, FirebaseControlAdmission admission)
    {
        try
        {
            FirebaseControlTokenExchange.UniqueObject(body);
            var state = body.GetProperty("state").GetString();
            var expected = new HashSet<string>(["state", "connection_id", "epoch", "request_ids",
                "retry_after_seconds", "activation_allowed"]);
            if (state == "recovered") expected.Add("page_full");
            if (!expected.SetEquals(body.EnumerateObject().Select(p => p.Name))
                || state is not ("recovered" or "throttled")
                || body.GetProperty("connection_id").GetString() != admission.Channel
                || body.GetProperty("epoch").GetString() != admission.Epoch
                || body.GetProperty("activation_allowed").ValueKind is not (JsonValueKind.False or JsonValueKind.True)
                || body.GetProperty("retry_after_seconds").GetInt32() is < 1 or > 75)
                throw new InvalidOperationException();
            var ids = body.GetProperty("request_ids").EnumerateArray().Select(v => v.GetString()!).ToArray();
            if (ids.Length > 8 || ids.Any(id => id is null || !FirebaseFirestoreControlListener.IsRequestId(id))
                || ids.Distinct(StringComparer.Ordinal).Count() != ids.Length
                || (state == "throttled" && ids.Length != 0)) throw new InvalidOperationException();
            return new(ids, state == "throttled" || body.GetProperty("page_full").GetBoolean());
        }
        catch (Exception) { throw new InvalidOperationException("firebaseControlRecoveryInvalid"); }
    }
}

// Preview-only. One dispatcher lives across all channel replacements so already
// claimed work is neither cancelled nor duplicated merely by lease renewal.
// All retry state is bounded; persistent server checkpoints additionally prevent
// a plugin process restart from resetting recovery query throttles.
internal static class FirebaseControlSupervisor
{
    internal static async IAsyncEnumerable<string> ReadAsync(
        Func<CancellationToken, Task<FirebaseControlAdmission>> admit,
        Func<FirebaseControlAdmission, CancellationToken, IAsyncEnumerable<string>> listen,
        Func<FirebaseControlAdmission, CancellationToken, Task<FirebaseControlRecovery>> recover,
        Action<string> evidence,
        [EnumeratorCancellation] CancellationToken cancellationToken,
        TimeProvider? timeProvider = null,
        Func<TimeSpan, CancellationToken, Task>? delay = null,
        Func<int>? jitter = null,
        Func<FirebaseControlAdmission, CancellationToken, Task<FirebaseRelayDemandRecovery>>? recoverDemands = null)
    {
        var clock = timeProvider ?? TimeProvider.System;
        delay ??= (duration, token) => Task.Delay(duration, clock, token);
        jitter ??= () => RandomNumberGenerator.GetInt32(0, 16);
        var failures = 0;
        long? lastRecovery = null;
        var recoveryInterval = TimeSpan.Zero;
        long? lastDemandRecovery = null;
        var demandRecoveryInterval = TimeSpan.Zero;
        string? previousChannel = null;
        string? previousEpoch = null;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            long? listeningBegan = null;
            FirebaseControlAdmission? admission = null;
            try
            {
                admission = await admit(cancellationToken).ConfigureAwait(false);
                admission.Check();
                if (admission.Channel == previousChannel || admission.Epoch == previousEpoch)
                    throw new InvalidOperationException("firebaseControlAdmissionReused");
                previousChannel = admission.Channel; previousEpoch = admission.Epoch;
            }
            catch (Exception)
            {
                cancellationToken.ThrowIfCancellationRequested();
                admission = null; Emit(evidence, "admission_failed");
            }
            if (admission is not null)
            {
                Emit(evidence, "channel_admitted");
                using var session = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                var leaseRemaining = admission.ExpiresAt - DateTimeOffset.UtcNow;
                session.CancelAfter(leaseRemaining > TimeSpan.Zero ? leaseRemaining : TimeSpan.Zero);
                IAsyncEnumerator<string>? reader = null;
                Task<bool>? read = null;
                var recoverMore = true;
                try
                {
                    reader = listen(admission, session.Token).GetAsyncEnumerator(session.Token);
                    while (!session.IsCancellationRequested)
                    {
                        FirebaseRelayDemandRecovery? recoveredDemands = null;
                        if (recoverDemands is not null && (lastDemandRecovery is null
                            || clock.GetElapsedTime(lastDemandRecovery.Value) >= demandRecoveryInterval))
                        {
                            // Independent bounded point-index recovery. Reserve
                            // before any call, including failure/lost response,
                            // and carry the interval across channel replacements.
                            lastDemandRecovery = clock.GetTimestamp();
                            // Server throttle independently jitters up to 75s.
                            // Reserve its upper bound even if the response is
                            // lost; a too-early throttled retry followed by a
                            // second interval could exhaust the original grant.
                            demandRecoveryInterval = TimeSpan.FromSeconds(75);
                            try
                            {
                                recoveredDemands = await recoverDemands(admission, session.Token).ConfigureAwait(false);
                                if (recoveredDemands.DemandIds.Count > 8
                                    || recoveredDemands.DemandIds.Any(id => !FirebaseRelayDemandAdmission.IsDemandId(id))
                                    || recoveredDemands.DemandIds.Distinct(StringComparer.Ordinal).Count() != recoveredDemands.DemandIds.Count)
                                    throw new InvalidOperationException();
                                Emit(evidence, "demand_recovery_checked");
                            }
                            catch (Exception)
                            {
                                cancellationToken.ThrowIfCancellationRequested();
                                recoveredDemands = null; Emit(evidence, "demand_recovery_deferred");
                            }
                        }
                        if (recoveredDemands is not null)
                            foreach (var id in recoveredDemands.DemandIds)
                            {
                                cancellationToken.ThrowIfCancellationRequested();
                                if (session.IsCancellationRequested) break;
                                yield return FirebaseRelayDemandAdmission.Prefix + id;
                            }
                        FirebaseControlRecovery? recovered = null;
                        if (recoverMore && (lastRecovery is null || clock.GetElapsedTime(lastRecovery.Value) >= recoveryInterval))
                        {
                            // Reserve before the call, including failure/lost response.
                            // Never shorten this interval using an untrusted Retry-After.
                            lastRecovery = clock.GetTimestamp();
                            recoveryInterval = TimeSpan.FromSeconds(60 + Math.Clamp(jitter(), 0, 15));
                            try
                            {
                                recovered = await recover(admission, session.Token).ConfigureAwait(false);
                                if (recovered.RequestIds.Count > 8
                                    || recovered.RequestIds.Any(id => id is null || !FirebaseFirestoreControlListener.IsRequestId(id))
                                    || recovered.RequestIds.Distinct(StringComparer.Ordinal).Count() != recovered.RequestIds.Count)
                                    throw new InvalidOperationException();
                                recoverMore = recovered.More;
                                Emit(evidence, "recovery_checked");
                            }
                            catch (Exception)
                            {
                                cancellationToken.ThrowIfCancellationRequested();
                                recovered = null; Emit(evidence, "recovery_deferred");
                            }
                        }
                        if (recovered is not null)
                            foreach (var id in recovered.RequestIds)
                            {
                                cancellationToken.ThrowIfCancellationRequested();
                                if (session.IsCancellationRequested) break;
                                yield return id;
                            }
                        if (session.IsCancellationRequested) break;
                        bool next;
                        try
                        {
                            listeningBegan ??= clock.GetTimestamp();
                            read ??= reader.MoveNextAsync().AsTask();
                            if ((recoverMore && lastRecovery is not null)
                                || (recoverDemands is not null && lastDemandRecovery is not null))
                            {
                                var remaining = recoverMore && lastRecovery is not null
                                    ? recoveryInterval - clock.GetElapsedTime(lastRecovery.Value) : TimeSpan.MaxValue;
                                if (recoverDemands is not null && lastDemandRecovery is not null)
                                {
                                    var demandRemaining = demandRecoveryInterval - clock.GetElapsedTime(lastDemandRecovery.Value);
                                    if (demandRemaining < remaining) remaining = demandRemaining;
                                }
                                if (remaining <= TimeSpan.Zero) continue;
                                using var wake = CancellationTokenSource.CreateLinkedTokenSource(session.Token);
                                var timer = delay(remaining, wake.Token);
                                var winner = await Task.WhenAny(read, timer).WaitAsync(session.Token).ConfigureAwait(false);
                                wake.Cancel();
                                try { await timer.ConfigureAwait(false); } catch (OperationCanceledException) { }
                                if (winner == timer) continue;
                            }
                            next = await read.WaitAsync(session.Token).ConfigureAwait(false);
                            read = null;
                        }
                        catch (Exception)
                        {
                            cancellationToken.ThrowIfCancellationRequested();
                            Emit(evidence, "channel_ended"); break;
                        }
                        if (!next) break;
                        cancellationToken.ThrowIfCancellationRequested();
                        if (session.IsCancellationRequested) break;
                        yield return reader.Current;
                    }
                }
                finally
                {
                    session.Cancel();
                    if (read is not null)
                        try { await read.ConfigureAwait(false); } catch (Exception) { }
                    if (reader is not null)
                        try { await reader.DisposeAsync().ConfigureAwait(false); }
                        catch (Exception) { Emit(evidence, "channel_cleanup_failed"); }
                }
            }
            cancellationToken.ThrowIfCancellationRequested();
            // Token exchange/recovery latency cannot reset the backoff. A
            // listener must survive at least 30 seconds; short flaps keep backing off.
            failures = listeningBegan is not null && clock.GetElapsedTime(listeningBegan.Value) >= TimeSpan.FromSeconds(30)
                ? 0 : Math.Min(failures + 1, 5);
            Emit(evidence, "renewal_wait");
            await delay(TimeSpan.FromSeconds(Math.Min(60, 5 * (1 << Math.Max(0, failures - 1)))
                + Math.Clamp(jitter(), 0, 15)), cancellationToken).ConfigureAwait(false);
        }
    }

    private static void Emit(Action<string> sink, string category)
    {
        try { sink(category); } catch (Exception) { /* Evidence cannot change authority. */ }
    }
}
