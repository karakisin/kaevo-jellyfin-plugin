using System.Runtime.CompilerServices;
using Google.Cloud.Firestore.V1;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class FirebaseIdleListenerTests
{
    private const string Epoch = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    private const string Path = "projects/demo-kaevo-migration/databases/(default)/documents/connector_signals/ccccccccccccccccccccccccccccccccccccccccccc";
    private static Document Snapshot(long revision, params string[] ids) => new() { Name = Path, Fields = {
        ["epoch"] = new Value { StringValue = Epoch }, ["revision"] = new Value { IntegerValue = revision },
        ["request_ids"] = new Value { ArrayValue = new ArrayValue { Values = { ids.Select(id => new Value { StringValue = id }) } } }
    }};

    [Fact]
    public void ProbeDoesNotConsumeHintsAndAcceptsALiveStreamThatAdvancedDuringProbe()
    {
        var state = new FirebaseFirestoreSignalState(Path, Epoch);
        state.Accept(Snapshot(1));
        Assert.False(state.HasMissedSnapshot(Snapshot(1)));
        Assert.True(state.HasMissedSnapshot(Snapshot(2, "r1")));
        Assert.Equal(new[] { "r1" }, state.Accept(Snapshot(2, "r1")));
        Assert.False(state.HasMissedSnapshot(Snapshot(1)));
        Assert.False(state.HasMissedSnapshot(Snapshot(2, "r1")));
        Assert.Throws<InvalidOperationException>(() => state.HasMissedSnapshot(Snapshot(2, "r2")));
        var wrong = Snapshot(3); wrong.Name += "other";
        Assert.Throws<InvalidOperationException>(() => state.HasMissedSnapshot(wrong));
        wrong = Snapshot(3); wrong.Fields["epoch"].StringValue = "wrong";
        Assert.Throws<InvalidOperationException>(() => state.HasMissedSnapshot(wrong));
    }

    private static async IAsyncEnumerable<string> LateHint(Task ready, Action disposed,
        [EnumeratorCancellation] CancellationToken token)
    {
        try { await ready.WaitAsync(token); yield return "live-request"; await Task.Delay(Timeout.Infinite, token); }
        finally { disposed(); }
    }

    [Fact]
    public async Task HealthyQuietStreamSurvivesMultipleProbesAndDeliversLateHint()
    {
        var ready = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var disposed = false; var probes = 0;
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        await using var reader = FirebaseControlReadFallback.ReadAsync(
            token => LateHint(ready.Task, () => disposed = true, token),
            _ => throw new Exception("fallback must not run"), () => TimeSpan.FromSeconds(20),
            DateTimeOffset.UtcNow.AddSeconds(10), stop.Token, stallWindow: TimeSpan.FromMilliseconds(10),
            confirmStall: _ => { Assert.False(disposed); if (++probes == 3) ready.SetResult(); return Task.FromResult(false); }).GetAsyncEnumerator();
        Assert.True(await reader.MoveNextAsync()); Assert.Equal("live-request", reader.Current);
        Assert.True(probes >= 3); Assert.False(disposed);
    }

    [Fact]
    public async Task HealthyIdleProbesCannotExtendLeaseExpiry()
    {
        var ready = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var disposed = false;
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        await using var reader = FirebaseControlReadFallback.ReadAsync(
            token => LateHint(ready.Task, () => disposed = true, token),
            _ => throw new Exception("expired lease must not fall back"),
            () => TimeSpan.FromSeconds(20), DateTimeOffset.UtcNow.AddMilliseconds(120), stop.Token,
            stallWindow: TimeSpan.FromMilliseconds(10), confirmStall: _ => Task.FromResult(false)).GetAsyncEnumerator();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await reader.MoveNextAsync());
        Assert.True(disposed);
        Assert.False(stop.IsCancellationRequested);
    }

    [Fact]
    public async Task ConfirmedMissStillDisposesLiveReaderBeforeFallback()
    {
        var ready = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var disposed = false;
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        await using var reader = FirebaseControlReadFallback.ReadAsync(
            token => LateHint(ready.Task, () => disposed = true, token),
            _ => { Assert.True(disposed); return Task.FromResult<IReadOnlyList<string>>(["recovered"]); },
            () => TimeSpan.FromSeconds(20), DateTimeOffset.UtcNow.AddSeconds(10), stop.Token,
            confirmStall: _ => Task.FromResult(true)).GetAsyncEnumerator();
        Assert.True(await reader.MoveNextAsync()); Assert.Equal("recovered", reader.Current);
    }

    [Theory]
    [InlineData("firebaseControlAccessDenied")]
    [InlineData("firebaseControlSignalInvalid")]
    [InlineData("firebaseControlLeaseExpired")]
    public async Task ProbeFailuresStayFailClosed(string category)
    {
        var ready = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        await using var reader = FirebaseControlReadFallback.ReadAsync(
            token => LateHint(ready.Task, () => {}, token), _ => throw new Exception("fallback forbidden"),
            () => TimeSpan.FromSeconds(20), DateTimeOffset.UtcNow.AddSeconds(10), stop.Token,
            confirmStall: _ => throw new InvalidOperationException(category)).GetAsyncEnumerator();
        Assert.Equal(category, (await Assert.ThrowsAsync<InvalidOperationException>(async () => await reader.MoveNextAsync())).Message);
    }
}
