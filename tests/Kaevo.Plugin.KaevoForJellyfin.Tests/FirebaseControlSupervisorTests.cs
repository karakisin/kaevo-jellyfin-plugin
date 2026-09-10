using System.Runtime.CompilerServices;
using System.Text.Json;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class FirebaseControlSupervisorTests
{
    private sealed class Clock : TimeProvider
    {
        private long ticks;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => ticks;
        public void Advance(TimeSpan duration) => ticks += duration.Ticks;
    }
    private static FirebaseControlAdmission Admission(char value = 'a') => new()
    {
        Channel = new string(value, 43), Epoch = new string(value, 32),
        CustomToken = "synthetic.custom.token", PushUid = "connector-push-" + new string('z', 43),
        ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(290),
    };
    private static async IAsyncEnumerable<string> Empty(FirebaseControlAdmission admission,
        [EnumeratorCancellation] CancellationToken token)
    { await Task.Yield(); token.ThrowIfCancellationRequested(); yield break; }

    [Fact]
    public async Task FailedAdmissionBacksOffAndCannotRecoverOrListen()
    {
        using var stop = new CancellationTokenSource(); var waits = new List<double>();
        var events = new List<string>(); var clock = new Clock();
        var source = FirebaseControlSupervisor.ReadAsync(_ => Task.FromException<FirebaseControlAdmission>(new Exception("private-key")),
            (_, _) => throw new Exception("listen_called"), (_, _) => throw new Exception("recover_called"),
            events.Add, stop.Token, clock, (duration, _) =>
            {
                waits.Add(duration.TotalSeconds); clock.Advance(duration);
                if (waits.Count == 7) stop.Cancel(); return Task.CompletedTask;
            }, () => 0);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => { await foreach (var _ in source) { } });
        Assert.Equal(new double[] { 5, 10, 20, 40, 60, 60, 60 }, waits);
        Assert.DoesNotContain("private-key", string.Join(",", events));
    }

    [Fact]
    public async Task FreshAdmissionRequiredAndOldListenerDisposedBeforeRenewal()
    {
        using var stop = new CancellationTokenSource(); var admitted = 0; var disposed = 0; var clock = new Clock();
        async IAsyncEnumerable<string> Listen(FirebaseControlAdmission a, [EnumeratorCancellation] CancellationToken token)
        {
            try { yield return "r" + admitted; await Task.Yield(); }
            finally { disposed++; }
        }
        var source = FirebaseControlSupervisor.ReadAsync(_ =>
        {
            Assert.Equal(admitted, disposed); admitted++; return Task.FromResult(Admission((char)('a' + admitted)));
        }, Listen, (_, _) => Task.FromResult(new FirebaseControlRecovery([], false)), _ => { }, stop.Token, clock,
            (duration, _) => { clock.Advance(duration); if (disposed == 3) stop.Cancel(); return Task.CompletedTask; }, () => 0);
        var ids = new List<string>();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => { await foreach (var id in source) ids.Add(id); });
        Assert.Equal(new[] { "r1", "r2", "r3" }, ids); Assert.Equal(3, disposed);
    }

    [Fact]
    public async Task ReusedAdmissionNeverReopensListener()
    {
        using var stop = new CancellationTokenSource(); var listens = 0; var attempts = 0;
        var source = FirebaseControlSupervisor.ReadAsync(_ =>
        { if (++attempts == 3) stop.Cancel(); return Task.FromResult(Admission()); },
            (a, token) => { listens++; return Empty(a, token); },
            (_, _) => Task.FromResult(new FirebaseControlRecovery([], false)), _ => { }, stop.Token,
            delay: (_, _) => Task.CompletedTask, jitter: () => 0);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => { await foreach (var _ in source) { } });
        Assert.Equal(1, listens);
    }

    [Fact]
    public async Task ReconnectAndRecoveryFailureCannotResetRecoveryInterval()
    {
        using var stop = new CancellationTokenSource(); var attempts = 0; var clock = new Clock();
        var calls = new List<long>();
        var source = FirebaseControlSupervisor.ReadAsync(_ => Task.FromResult(Admission((char)('a' + ++attempts))),
            Empty, (_, _) => { calls.Add(clock.GetTimestamp()); throw new Exception("private-provider"); },
            _ => { }, stop.Token, clock, (duration, _) =>
            { clock.Advance(duration); if (attempts == 6) stop.Cancel(); return Task.CompletedTask; }, () => 0);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => { await foreach (var _ in source) { } });
        Assert.True(calls.Count >= 2);
        for (var i = 1; i < calls.Count; i++) Assert.True(calls[i] - calls[i - 1] >= TimeSpan.FromSeconds(60).Ticks);
    }

    [Fact]
    public async Task FullRecoveryPageSchedulesAnotherBoundedPageWithoutReconnecting()
    {
        using var stop = new CancellationTokenSource(); var clock = new Clock(); var calls = 0; var disposed = false;
        async IAsyncEnumerable<string> Idle(FirebaseControlAdmission a, [EnumeratorCancellation] CancellationToken token)
        {
            try { await Task.Delay(Timeout.Infinite, token); yield break; }
            finally { disposed = true; }
        }
        var source = FirebaseControlSupervisor.ReadAsync(_ => Task.FromResult(Admission()), Idle,
            (_, _) => Task.FromResult(new FirebaseControlRecovery(["r" + ++calls], calls == 1)), _ => { }, stop.Token, clock,
            (duration, _) => { clock.Advance(duration); return Task.CompletedTask; }, () => 0);
        var ids = new List<string>();
        await foreach (var id in source)
        { ids.Add(id); if (ids.Count == 2) break; }
        Assert.Equal(new[] { "r1", "r2" }, ids); Assert.True(disposed);
        Assert.Equal(TimeSpan.FromSeconds(60).Ticks, clock.GetTimestamp());
    }

    [Fact]
    public async Task HostCancellationStopsIdleReadAndDoesNotRenew()
    {
        using var stop = new CancellationTokenSource(); var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var attempts = 0; var disposed = false;
        async IAsyncEnumerable<string> Idle(FirebaseControlAdmission a, [EnumeratorCancellation] CancellationToken token)
        {
            try { entered.SetResult(); await Task.Delay(Timeout.Infinite, token); yield break; }
            finally { disposed = true; }
        }
        var source = FirebaseControlSupervisor.ReadAsync(_ => { attempts++; return Task.FromResult(Admission()); }, Idle,
            (_, _) => Task.FromResult(new FirebaseControlRecovery([], false)), _ => { }, stop.Token);
        var run = Task.Run(async () => { await foreach (var _ in source) { } });
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5)); stop.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Equal(1, attempts); Assert.True(disposed);
    }

    [Fact]
    public async Task DispatcherRetainsInFlightDeduplicationAcrossRenewal()
    {
        using var stop = new CancellationTokenSource(); var clock = new Clock(); var attempts = 0; var claims = 0;
        var released = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        async IAsyncEnumerable<string> Listen(FirebaseControlAdmission a, [EnumeratorCancellation] CancellationToken token)
        { yield return "same-request"; await Task.Yield(); }
        var source = FirebaseControlSupervisor.ReadAsync(_ => Task.FromResult(Admission((char)('a' + ++attempts))), Listen,
            (_, _) => Task.FromResult(new FirebaseControlRecovery([], false)), _ => { }, stop.Token, clock,
            (duration, _) => { clock.Advance(duration); if (attempts == 3) { released.SetResult(); stop.Cancel(); } return Task.CompletedTask; }, () => 0);
        var run = FirebaseControlDispatch.RunAsync(source,
            (id, _) => { claims++; return Task.FromResult<string?>(id); }, (_, _) => released.Task, id => id, 4, stop.Token);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Equal(1, claims); Assert.Equal(3, attempts);
    }

    [Fact]
    public async Task EvidenceSinkFailureCannotChangeValidDelivery()
    {
        using var stop = new CancellationTokenSource();
        var source = FirebaseControlSupervisor.ReadAsync(_ => Task.FromResult(Admission()), Empty,
            (_, _) => Task.FromResult(new FirebaseControlRecovery(["r1"], false)), _ => throw new Exception("log-failed"), stop.Token);
        await foreach (var id in source) { Assert.Equal("r1", id); break; }
    }

    private static Dictionary<string, object> RecoveryBody() => new()
    {
        ["state"] = "recovered", ["connection_id"] = new string('a', 43), ["epoch"] = new string('a', 32),
        ["request_ids"] = new[] { "r1" }, ["retry_after_seconds"] = 60, ["activation_allowed"] = false, ["page_full"] = false,
    };

    [Fact]
    public async Task MissedDemandRecoveryContinuesWhileCommandRecoveryIsIdle()
    {
        using var stop = new CancellationTokenSource(); var clock = new Clock();
        var commands = 0; var demands = 0; var admits = 0; var disposed = false;
        var id = Guid.NewGuid().ToString();
        async IAsyncEnumerable<string> Idle(FirebaseControlAdmission a, [EnumeratorCancellation] CancellationToken token)
        {
            try { await Task.Delay(Timeout.Infinite, token); yield break; }
            finally { disposed = true; }
        }
        var source = FirebaseControlSupervisor.ReadAsync(_ => { admits++; return Task.FromResult(Admission()); }, Idle,
            (_, _) => { commands++; return Task.FromResult(new FirebaseControlRecovery([], false)); },
            _ => { }, stop.Token, clock, (duration, _) => { clock.Advance(duration); return Task.CompletedTask; }, () => 0,
            recoverDemands: (_, _) => Task.FromResult(new FirebaseRelayDemandRecovery(++demands == 1 ? [] : [id])));
        await foreach (var hint in source) { Assert.Equal("relay-demand:" + id, hint); break; }
        Assert.Equal(1, commands); Assert.Equal(2, demands); Assert.Equal(1, admits); Assert.True(disposed);
        Assert.Equal(TimeSpan.FromSeconds(75).Ticks, clock.GetTimestamp());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FailedOrOversizedDemandRecoveryRemainsThrottledAcrossRenewals(bool oversized)
    {
        using var stop = new CancellationTokenSource(); var attempts = 0; var clock = new Clock();
        var calls = new List<long>(); var evidence = new List<string>();
        var source = FirebaseControlSupervisor.ReadAsync(_ => Task.FromResult(Admission((char)('a' + ++attempts))), Empty,
            (_, _) => Task.FromResult(new FirebaseControlRecovery([], false)), evidence.Add, stop.Token, clock,
            (duration, _) => { clock.Advance(duration); if (attempts == 6) stop.Cancel(); return Task.CompletedTask; }, () => 0,
            recoverDemands: (_, _) =>
            {
                calls.Add(clock.GetTimestamp());
                if (!oversized) throw new Exception("private-provider");
                return Task.FromResult(new FirebaseRelayDemandRecovery(Enumerable.Range(0, 9).Select(_ => Guid.NewGuid().ToString()).ToArray()));
            });
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => { await foreach (var _ in source) Assert.Fail("invalid hint emitted"); });
        Assert.True(calls.Count >= 2);
        for (var i = 1; i < calls.Count; i++) Assert.True(calls[i] - calls[i - 1] >= TimeSpan.FromSeconds(60).Ticks);
        Assert.DoesNotContain("private-provider", string.Join(",", evidence));
        Assert.Contains("demand_recovery_deferred", evidence);
        for (var i = 1; i < calls.Count; i++) Assert.True(calls[i] - calls[i - 1] >= TimeSpan.FromSeconds(75).Ticks);
    }

    [Fact]
    public async Task DemandRecoveryHintsStillRequireExactSignedAdmissionBeforeOpeningPool()
    {
        using var stop = new CancellationTokenSource(); var calls = 0; var delivered = false;
        var id = Guid.NewGuid().ToString();
        var source = FirebaseControlSupervisor.ReadAsync(_ => Task.FromResult(Admission()), Empty,
            (_, _) => { stop.Cancel(); return Task.FromResult(new FirebaseControlRecovery([], false)); }, _ => { }, stop.Token,
            recoverDemands: (_, _) => Task.FromResult(new FirebaseRelayDemandRecovery([id])));
        var filtered = FirebaseRelayDemandAdmission.FilterAsync(source, (_, _) =>
        { calls++; throw new InvalidOperationException(); }, (_, _) => { delivered = true; return ValueTask.CompletedTask; }, _ => { }, stop.Token);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => { await foreach (var _ in filtered) Assert.Fail("hint became command"); });
        Assert.Equal(2, calls); Assert.False(delivered);
    }
    [Theory]
    [InlineData("state", "claimed")]
    [InlineData("connection_id", "wrong")]
    [InlineData("epoch", "wrong")]
    [InlineData("retry_after_seconds", 0)]
    [InlineData("retry_after_seconds", 76)]
    [InlineData("extra", "private")]
    public void WrongRecoveryShapeOrScopeIsRejected(string field, object value)
    {
        var body = RecoveryBody(); body[field] = value;
        var error = Assert.Throws<InvalidOperationException>(() => FirebaseControlRecovery.Parse(JsonSerializer.SerializeToElement(body), Admission()));
        Assert.Equal("firebaseControlRecoveryInvalid", error.Message);
    }
    [Theory]
    [InlineData(9, false)]
    [InlineData(2, true)]
    public void OversizedOrDuplicateRecoveryBatchIsRejected(int count, bool duplicate)
    {
        var body = RecoveryBody(); body["request_ids"] = Enumerable.Range(0, count).Select(i => duplicate ? "r1" : "r" + i).ToArray();
        Assert.Throws<InvalidOperationException>(() => FirebaseControlRecovery.Parse(JsonSerializer.SerializeToElement(body), Admission()));
    }
}
