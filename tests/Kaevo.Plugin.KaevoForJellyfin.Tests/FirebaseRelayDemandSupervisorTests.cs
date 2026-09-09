using System.Threading.Channels;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class FirebaseRelayDemandSupervisorTests
{
    private sealed class Clock : TimeProvider
    {
        private long ticks;
        private readonly List<(long Due, TaskCompletionSource Done)> timers = [];
        internal int Timers { get { lock (timers) return timers.Count(t => !t.Done.Task.IsCompleted); } }
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => Interlocked.Read(ref ticks);
        public override DateTimeOffset GetUtcNow() => DateTimeOffset.FromUnixTimeSeconds(1_800_000_000).AddTicks(GetTimestamp());
        internal Task Delay(TimeSpan value, CancellationToken token)
        {
            var done = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var registration = token.Register(() => done.TrySetCanceled(token));
            lock (timers) timers.Add((value == Timeout.InfiniteTimeSpan ? long.MaxValue : GetTimestamp() + value.Ticks, done));
            return Complete();
            async Task Complete() { try { await done.Task; } finally { registration.Dispose(); } }
        }
        internal void Advance(double seconds)
        {
            Interlocked.Add(ref ticks, TimeSpan.FromSeconds(seconds).Ticks);
            lock (timers)
                foreach (var timer in timers.Where(t => t.Due <= GetTimestamp()).ToArray()) timer.Done.TrySetResult();
        }
    }
    private static FirebaseRelayDemand Demand(Clock clock, int seconds = 120) => new(Guid.NewGuid().ToString("D"), clock.GetUtcNow(), clock.GetUtcNow().AddSeconds(seconds));
    private static async Task Until(Func<bool> check)
    {
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while (!check()) await Task.Delay(1, stop.Token);
    }

    [Fact]
    public void IdleOwnerHasNoDemandAndDuplicateCannotExtendTheLease()
    {
        var clock = new Clock(); var window = new FirebaseRelayDemandWindow(clock);
        Assert.False(window.Snapshot().Needed);
        var demand = Demand(clock); window.Admit(demand); clock.Advance(100); window.Admit(demand);
        Assert.Equal(TimeSpan.FromSeconds(20), window.Snapshot().Remaining);
        clock.Advance(20); Assert.False(window.Snapshot().Needed);
        Assert.Throws<InvalidOperationException>(() => window.Admit(demand));
    }

    [Theory]
    [InlineData("invalid-id")]
    [InlineData("future-issued")]
    [InlineData("expired")]
    [InlineData("long-lease")]
    [InlineData("reversed")]
    public void MalformedDemandNeverWakesChannels(string variant)
    {
        var clock = new Clock(); var window = new FirebaseRelayDemandWindow(clock); var demand = Demand(clock);
        demand = variant switch
        {
            "invalid-id" => demand with { Id = "synthetic-secret" },
            "future-issued" => demand with { IssuedAt = clock.GetUtcNow().AddSeconds(1) },
            "expired" => demand with { ExpiresAt = clock.GetUtcNow() },
            "long-lease" => demand with { ExpiresAt = clock.GetUtcNow().AddSeconds(121) },
            _ => demand with { ExpiresAt = demand.IssuedAt.AddSeconds(-1) },
        };
        var error = Assert.Throws<InvalidOperationException>(() => window.Admit(demand));
        Assert.Equal("firebaseRelayDemandInvalid", error.Message); Assert.False(window.Snapshot().Needed);
    }

    [Fact]
    public void SameDemandIdCannotChangeExpiry()
    {
        var clock = new Clock(); var window = new FirebaseRelayDemandWindow(clock); var demand = Demand(clock, 60);
        window.Admit(demand);
        Assert.Throws<InvalidOperationException>(() => window.Admit(demand with { ExpiresAt = demand.ExpiresAt.AddSeconds(1) }));
        Assert.Equal(TimeSpan.FromSeconds(60), window.Snapshot().Remaining);
    }

    [Fact]
    public void AdmissionMemoryIsBoundedAndExpiredEntriesCanBeReclaimed()
    {
        var clock = new Clock(); var window = new FirebaseRelayDemandWindow(clock);
        for (var n = 0; n < 128; n++) window.Admit(Demand(clock, 1));
        Assert.Throws<InvalidOperationException>(() => window.Admit(Demand(clock)));
        clock.Advance(2); window.Admit(Demand(clock)); Assert.True(window.Snapshot().Needed);
    }

    [Fact]
    public void LongDirectResponseIsNotCancelledByTheTransportIdleTimer()
    {
        var clock = new Clock(); var window = new FirebaseRelayDemandWindow(clock); window.Admit(Demand(clock));
        using var request = window.BeginVerifiedRequest(); clock.Advance(3600);
        Assert.Equal(Timeout.InfiniteTimeSpan, window.Snapshot().Remaining);
        request.RecordBodyProgress(); request.Dispose(); request.Dispose();
        Assert.Equal(FirebaseRelayDemandWindow.IdleGrace, window.Snapshot().Remaining);
        clock.Advance(310); Assert.False(window.Snapshot().Needed);
    }

    [Fact]
    public void ManualPauseRetainsTheFullExistingFiveMinuteGrantWindow()
    {
        var clock = new Clock(); var window = new FirebaseRelayDemandWindow(clock); window.Admit(Demand(clock));
        using (var first = window.BeginVerifiedRequest()) { first.RecordBodyProgress(); }
        clock.Advance(300); Assert.True(window.Snapshot().Needed);
        using (var resumed = window.BeginVerifiedRequest()) { resumed.RecordBodyProgress(); }
        clock.Advance(300); Assert.True(window.Snapshot().Needed);
        clock.Advance(10); Assert.False(window.Snapshot().Needed);
    }

    [Fact]
    public void DisposedRequestCannotKeepAnotherViewersTransportWarm()
    {
        var clock = new Clock(); var window = new FirebaseRelayDemandWindow(clock);
        var closed = window.BeginVerifiedRequest(); closed.Dispose(); clock.Advance(1);
        using var current = window.BeginVerifiedRequest(); clock.Advance(100);
        closed.RecordBodyProgress(); current.Dispose();
        Assert.Equal(TimeSpan.FromSeconds(210), window.Snapshot().Remaining);
    }

    [Fact]
    public void FailedOrStalledRequestReleaseDoesNotInventBodyProgress()
    {
        var clock = new Clock(); var window = new FirebaseRelayDemandWindow(clock);
        var request = window.BeginVerifiedRequest(); clock.Advance(311); request.Dispose();
        Assert.False(window.Snapshot().Needed);
        window.Stop(); Assert.Throws<OperationCanceledException>(() => window.BeginVerifiedRequest());
        Assert.Throws<InvalidOperationException>(() => window.Admit(Demand(clock)));
    }

    [Fact]
    public async Task IdleInputHasZeroChannelAttemptsAndZeroPollingTimers()
    {
        var clock = new Clock(); var demands = Channel.CreateUnbounded<FirebaseRelayDemand>(); var calls = 0;
        using var stop = new CancellationTokenSource();
        var run = FirebaseRelayDemandSupervisor.RunAsync(demands.Reader.ReadAllAsync(),
            (_, _, _) => { calls++; return Task.CompletedTask; }, _ => { }, stop.Token, clock, clock.Delay);
        clock.Advance(86400); await Task.Yield(); Assert.Equal(0, calls); Assert.Equal(0, clock.Timers);
        demands.Writer.Complete(); await run.WaitAsync(TimeSpan.FromSeconds(5)); Assert.Equal(0, calls);
    }

    [Fact]
    public async Task CoalescesViewersIntoThreeChannelsParksAndCanWakeAgain()
    {
        var clock = new Clock(); var demands = Channel.CreateUnbounded<FirebaseRelayDemand>();
        var opened = 0; var closed = 0; var active = 0; var maximum = 0; var events = new List<string>();
        using var stop = new CancellationTokenSource();
        async Task ChannelRun(int index, FirebaseRelayDemandWindow window, CancellationToken token)
        {
            Interlocked.Increment(ref opened); var count = Interlocked.Increment(ref active); maximum = Math.Max(maximum, count);
            try { await Task.Delay(Timeout.Infinite, token); }
            finally { Interlocked.Decrement(ref active); Interlocked.Increment(ref closed); }
        }
        var run = FirebaseRelayDemandSupervisor.RunAsync(demands.Reader.ReadAllAsync(), ChannelRun,
            category => { lock (events) events.Add(category); }, stop.Token, clock, clock.Delay);
        var first = Demand(clock, 20); demands.Writer.TryWrite(first); demands.Writer.TryWrite(first); demands.Writer.TryWrite(Demand(clock, 20));
        await Until(() => opened == 3 && clock.Timers > 0); Assert.Equal(3, maximum);
        clock.Advance(21); await Until(() => closed == 3); Assert.Equal(0, active);
        demands.Writer.TryWrite(Demand(clock, 20)); await Until(() => opened == 6 && clock.Timers > 0);
        demands.Writer.Complete(); clock.Advance(21); await run.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(6, closed); Assert.Equal(3, maximum); Assert.Equal(0, clock.Timers);
    }

    [Fact]
    public async Task RequestActivityKeepsPoolAliveAfterInputCompletionUntilItsIdleWindowEnds()
    {
        var clock = new Clock(); var demands = Channel.CreateUnbounded<FirebaseRelayDemand>();
        FirebaseRelayDemandWindow.Request? activity = null; var entered = 0;
        var run = FirebaseRelayDemandSupervisor.RunAsync(demands.Reader.ReadAllAsync(), async (index, window, token) =>
        {
            if (index == 0) activity = window.BeginVerifiedRequest();
            Interlocked.Increment(ref entered); await Task.Delay(Timeout.Infinite, token);
        }, _ => { }, CancellationToken.None, clock, clock.Delay);
        demands.Writer.TryWrite(Demand(clock, 1)); await Until(() => entered == 3 && clock.Timers > 0);
        demands.Writer.Complete(); clock.Advance(1000); Assert.False(run.IsCompleted);
        activity!.RecordBodyProgress(); activity.Dispose(); await Until(() => clock.Timers > 0);
        clock.Advance(311); await run.WaitAsync(TimeSpan.FromSeconds(5)); Assert.Equal(0, clock.Timers);
    }

    [Fact]
    public async Task CancellationDrainsChannelsAndAllOwnerTimers()
    {
        var clock = new Clock(); var demands = Channel.CreateUnbounded<FirebaseRelayDemand>(); var entered = 0; var closed = 0;
        using var stop = new CancellationTokenSource();
        var run = FirebaseRelayDemandSupervisor.RunAsync(demands.Reader.ReadAllAsync(), async (_, window, token) =>
        {
            using var activity = window.BeginVerifiedRequest(); Interlocked.Increment(ref entered);
            try { await Task.Delay(Timeout.Infinite, token); } finally { Interlocked.Increment(ref closed); }
        }, _ => throw new Exception("evidence-secret"), stop.Token, clock, clock.Delay);
        demands.Writer.TryWrite(Demand(clock)); await Until(() => entered == 3 && clock.Timers > 0); stop.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Equal(3, closed); Assert.Equal(0, clock.Timers);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ShortEofOrFailureBacksOffWithoutExtendingDemand(bool fail)
    {
        var clock = new Clock(); var demands = Channel.CreateUnbounded<FirebaseRelayDemand>(); var attempts = 0;
        var waits = new List<double>(); var events = new List<string>(); using var stop = new CancellationTokenSource();
        Task Delay(TimeSpan duration, CancellationToken token)
        { lock (waits) waits.Add(duration.TotalSeconds); return clock.Delay(duration, token); }
        var run = FirebaseRelayDemandSupervisor.RunAsync(demands.Reader.ReadAllAsync(), (_, _, _) =>
        { Interlocked.Increment(ref attempts); return fail ? Task.FromException(new Exception("private-endpoint")) : Task.CompletedTask; },
            category => { lock (events) events.Add(category); }, stop.Token, clock, Delay);
        demands.Writer.TryWrite(Demand(clock)); await Until(() => attempts == 3 && clock.Timers == 4);
        foreach (var advance in new[] { 1, 2, 4, 8, 16, 30 })
        {
            var before = attempts; clock.Advance(advance); await Until(() => attempts == before + 3 && clock.Timers == 4);
        }
        Assert.Equal(21, attempts); Assert.DoesNotContain("private-endpoint", string.Join(",", events));
        demands.Writer.Complete(); clock.Advance(121); await run.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(0, clock.Timers);
        foreach (var retry in new double[] { 1, 2, 4, 8, 16, 30 }) Assert.Contains(retry, waits);
    }

    [Fact]
    public async Task MalformedInputStopsExistingPoolAndReportsOnlyFixedCategory()
    {
        var clock = new Clock(); var demands = Channel.CreateUnbounded<FirebaseRelayDemand>(); var entered = 0; var closed = 0;
        var run = FirebaseRelayDemandSupervisor.RunAsync(demands.Reader.ReadAllAsync(), async (_, _, token) =>
        {
            Interlocked.Increment(ref entered); try { await Task.Delay(Timeout.Infinite, token); }
            finally { Interlocked.Increment(ref closed); }
        }, _ => { }, CancellationToken.None, clock, clock.Delay);
        demands.Writer.TryWrite(Demand(clock)); await Until(() => entered == 3 && clock.Timers > 0);
        demands.Writer.TryWrite(Demand(clock) with { Id = "private-data" });
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => run.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Equal("firebaseRelayDemandStreamFailed", error.Message); Assert.Equal(3, closed); Assert.Equal(0, clock.Timers);
    }
}
