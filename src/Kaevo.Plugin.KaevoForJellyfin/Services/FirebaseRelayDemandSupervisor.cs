namespace Kaevo.Plugin.KaevoForJellyfin.Services;

// Transport lifetime only, never an authorization verifier. The future runtime
// owner must obtain each demand from the exact signed, handoff-checked backend
// before supplying it here. An opaque Firestore hint is NOT admitted demand.
internal sealed record FirebaseRelayDemand(string Id, DateTimeOffset IssuedAt, DateTimeOffset ExpiresAt);

internal sealed class FirebaseRelayDemandWindow
{
    internal static readonly TimeSpan IdleGrace = TimeSpan.FromSeconds(310);
    private readonly TimeProvider clock;
    private readonly object gate = new();
    private readonly Dictionary<string, FirebaseRelayDemand> admitted = new(StringComparer.Ordinal);
    private TaskCompletionSource changed = NewSignal();
    private long? warmStarted;
    private TimeSpan warmDuration;
    private long? lastActivity;
    private int requests;
    private bool stopped;

    internal FirebaseRelayDemandWindow(TimeProvider clock) => this.clock = clock;
    private static TaskCompletionSource NewSignal() => new(TaskCreationOptions.RunContinuationsAsynchronously);
    private void Pulse() { var old = changed; changed = NewSignal(); old.TrySetResult(); }

    internal void Admit(FirebaseRelayDemand demand)
    {
        lock (gate)
        {
            var now = clock.GetUtcNow();
            if (stopped || demand is null || !Guid.TryParseExact(demand.Id, "D", out _)
                || demand.IssuedAt > now || demand.ExpiresAt <= now
                || demand.ExpiresAt - demand.IssuedAt > TimeSpan.FromSeconds(120)
                || demand.ExpiresAt <= demand.IssuedAt)
                throw new InvalidOperationException("firebaseRelayDemandInvalid");
            if (admitted.TryGetValue(demand.Id, out var previous))
            {
                if (previous != demand) throw new InvalidOperationException("firebaseRelayDemandConflict");
                return; // A repeated hint/receipt cannot refresh a local lease.
            }
            foreach (var id in admitted.Where(p => p.Value.ExpiresAt <= now).Select(p => p.Key).ToArray())
                admitted.Remove(id);
            if (admitted.Count >= 128) throw new InvalidOperationException("firebaseRelayDemandCapacity");
            admitted.Add(demand.Id, demand);
            var remaining = demand.ExpiresAt - now;
            var current = warmStarted is null ? TimeSpan.Zero : warmDuration - clock.GetElapsedTime(warmStarted.Value);
            if (remaining > current) { warmStarted = clock.GetTimestamp(); warmDuration = remaining; }
            Pulse();
        }
    }

    // Call only AFTER the retained grant AND exact resource resolver succeed,
    // never on raw WebSocket messages, ping/pong, tickets or failed signatures.
    internal Request BeginVerifiedRequest()
    {
        lock (gate)
        {
            if (stopped) throw new OperationCanceledException();
            requests++; lastActivity = clock.GetTimestamp(); Pulse();
            return new Request(this);
        }
    }

    private void RecordVerifiedBodyProgress()
    {
        lock (gate)
        {
            if (stopped || requests == 0) return;
            lastActivity = clock.GetTimestamp(); Pulse();
        }
    }

    internal sealed class Request(FirebaseRelayDemandWindow owner) : KaevoCloudConnectorService.IRelayRequestActivity
    {
        private readonly object gate = new();
        private FirebaseRelayDemandWindow? current = owner;
        public void RecordBodyProgress() { lock (gate) current?.RecordVerifiedBodyProgress(); }
        public void Dispose()
        {
            lock (gate)
            {
                var value = current; current = null;
                if (value is null) return;
                lock (value.gate) { value.requests--; value.Pulse(); }
            }
        }
    }

    internal (bool Needed, TimeSpan Remaining, Task Changed) Snapshot()
    {
        lock (gate)
        {
            if (stopped) return (false, TimeSpan.Zero, changed.Task);
            if (requests > 0) return (true, Timeout.InfiniteTimeSpan, changed.Task);
            var warm = warmStarted is null ? TimeSpan.Zero : warmDuration - clock.GetElapsedTime(warmStarted.Value);
            var idle = lastActivity is null ? TimeSpan.Zero : IdleGrace - clock.GetElapsedTime(lastActivity.Value);
            var remaining = warm > idle ? warm : idle;
            return (remaining > TimeSpan.Zero, remaining > TimeSpan.Zero ? remaining : TimeSpan.Zero, changed.Task);
        }
    }

    internal void Notify() { lock (gate) Pulse(); }
    internal void Stop() { lock (gate) { stopped = true; Pulse(); } }
}

// Preview-only, not selected by the installed connector's normal supervisor.
// Zero channels/ticket calls/timers while parked. One three-channel pool covers
// all admitted viewers. Cancellation drains the old pool before a replacement.
// Existing request deadlines, grant activation, manual pause and HTTP semantics
// belong to their retained owners and are not redefined by this transport owner.
internal sealed class FirebaseRelayStartupRaceException : Exception
{
    internal FirebaseRelayStartupRaceException() : base("firebaseRelayStartupRace") { }
}

internal static class FirebaseRelayDemandSupervisor
{
    internal static async Task RunAsync(IAsyncEnumerable<FirebaseRelayDemand> demands,
        Func<int, FirebaseRelayDemandWindow, CancellationToken, Task> runChannel,
        Action<string> evidence, CancellationToken cancellationToken,
        TimeProvider? timeProvider = null, Func<TimeSpan, CancellationToken, Task>? delay = null)
    {
        var clock = timeProvider ?? TimeProvider.System;
        delay ??= (duration, token) => Task.Delay(duration, clock, token);
        var window = new FirebaseRelayDemandWindow(clock);
        using var life = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        CancellationTokenSource? poolStop = null;
        Task? pool = null;
        async Task Feed()
        {
            try
            {
                await foreach (var demand in demands.WithCancellation(life.Token).ConfigureAwait(false))
                    window.Admit(demand);
            }
            catch (OperationCanceledException) when (life.IsCancellationRequested) { throw; }
            catch (Exception) { throw new InvalidOperationException("firebaseRelayDemandStreamFailed"); }
            finally { window.Notify(); }
        }
        var feed = Feed();
        try
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (feed.IsFaulted || feed.IsCanceled) await feed.ConfigureAwait(false);
                var state = window.Snapshot();
                if (!state.Needed)
                {
                    if (pool is not null)
                    {
                        poolStop!.Cancel();
                        try { await pool.ConfigureAwait(false); } catch (OperationCanceledException) { }
                        poolStop.Dispose(); poolStop = null; pool = null;
                        Emit(evidence, "media_parked");
                        // A demand can arrive during pool cleanup. Re-evaluate
                        // before observing completion or waiting on its signal.
                        continue;
                    }
                    if (feed.IsCompleted) { await feed.ConfigureAwait(false); return; }
                    await Task.WhenAny(state.Changed, feed).WaitAsync(life.Token).ConfigureAwait(false);
                    continue;
                }
                if (pool is null)
                {
                    poolStop = CancellationTokenSource.CreateLinkedTokenSource(life.Token);
                    pool = Task.WhenAll(Enumerable.Range(0, 3).Select(index => Channel(index, poolStop.Token)));
                    Emit(evidence, "media_demand_opened");
                }
                using var wake = CancellationTokenSource.CreateLinkedTokenSource(life.Token);
                var timer = delay(state.Remaining, wake.Token);
                // A completed (normal) input must not cause a hot loop while
                // active media drains. An unexpected worker exit is surfaced.
                var inputs = feed.IsCompleted ? new[] { state.Changed, timer, pool } : new[] { state.Changed, timer, pool, feed };
                Task winner;
                try { winner = await Task.WhenAny(inputs).WaitAsync(life.Token).ConfigureAwait(false); }
                finally
                {
                    wake.Cancel();
                    try { await timer.ConfigureAwait(false); } catch (OperationCanceledException) when (wake.IsCancellationRequested) { }
                }
                if (winner == pool) { await pool.ConfigureAwait(false); throw new InvalidOperationException("firebaseRelayPoolEnded"); }
            }
        }
        finally
        {
            window.Stop(); life.Cancel(); poolStop?.Cancel();
            try { await feed.ConfigureAwait(false); } catch (Exception) { }
            if (pool is not null) try { await pool.ConfigureAwait(false); } catch (Exception) { }
            poolStop?.Dispose();
            Emit(evidence, "media_owner_stopped");
        }

        async Task Channel(int index, CancellationToken token)
        {
            var retry = 1;
            var startupRetryUsed = false;
            while (true)
            {
                token.ThrowIfCancellationRequested();
                var began = clock.GetTimestamp();
                try { await runChannel(index, window, token).ConfigureAwait(false); }
                catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
                catch (FirebaseRelayStartupRaceException) when (!startupRetryUsed)
                {
                    // A verified ticket became available before the relay HTTP
                    // listener. Give this transition one short retry, without
                    // carrying the earlier ticket-wait backoff into playback.
                    startupRetryUsed = true;
                    retry = 1;
                    Emit(evidence, "media_startup_retry");
                }
                catch (Exception) { Emit(evidence, "media_channel_retry"); }
                token.ThrowIfCancellationRequested();
                // EOF and quick success must back off just like a failed socket.
                // An empty/failed transport does not extend admitted demand.
                if (clock.GetElapsedTime(began) >= TimeSpan.FromSeconds(30)) retry = 1;
                await delay(TimeSpan.FromSeconds(retry), token).ConfigureAwait(false);
                retry = Math.Min(retry * 2, 30);
            }
        }
    }

    private static void Emit(Action<string> sink, string category)
    { try { sink(category); } catch (Exception) { } }
}
