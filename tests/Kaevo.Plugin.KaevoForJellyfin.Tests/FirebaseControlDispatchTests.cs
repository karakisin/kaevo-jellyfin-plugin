using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Threading.Channels;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class FirebaseControlDispatchTests
{
    private static TaskCompletionSource Ready() => new(TaskCreationOptions.RunContinuationsAsynchronously);
    private static Channel<string> Queue(params string[] ids)
    {
        var queue = Channel.CreateUnbounded<string>();
        foreach (var id in ids) queue.Writer.TryWrite(id);
        return queue;
    }
    private static Task Run(Channel<string> queue, Func<string, CancellationToken, Task<string?>> claim,
        Func<string, CancellationToken, Task> handle, CancellationToken token = default, int concurrency = 4)
        => FirebaseControlDispatch.RunAsync(queue.Reader.ReadAllAsync(), claim, handle, id => id, concurrency, token);

    [Theory]
    [InlineData(0)]
    [InlineData(5)]
    public async Task InvalidConcurrencyCannotClaim(int concurrency)
    {
        var count = 0;
        await Assert.ThrowsAsync<InvalidOperationException>(() => Run(Queue("r1"),
            (_, _) => { count++; return Task.FromResult<string?>("r1"); },
            (_, _) => Task.CompletedTask, concurrency: concurrency));
        Assert.Equal(0, count);
    }

    [Fact]
    public async Task DeniedClaimsNeverReachProvider()
    {
        var queue = Queue("r1", "r2"); queue.Writer.Complete(); var count = 0;
        await Run(queue, (_, _) => Task.FromResult<string?>(null),
            (_, _) => { count++; return Task.CompletedTask; });
        Assert.Equal(0, count);
    }

    [Fact]
    public async Task DuplicateInFlightHintIsCoalesced()
    {
        var queue = Queue("r1", "r1", "r2"); queue.Writer.Complete();
        var entered = Ready(); var release = Ready(); var claims = new ConcurrentQueue<string>();
        var run = Run(queue, (id, _) => { claims.Enqueue(id); return Task.FromResult<string?>(id); },
            (_, _) => { if (claims.Count == 2) entered.TrySetResult(); return release.Task; });
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal(new[] { "r1", "r2" }, claims);
        }
        finally { release.TrySetResult(); }
        await run.WaitAsync(TimeSpan.FromSeconds(5));
    }

    [Fact]
    public async Task SaturationDoesNotClaimMoreThanFourAndDrainsAll()
    {
        var queue = Queue(Enumerable.Range(1, 8).Select(i => "r" + i).ToArray()); queue.Writer.Complete();
        var entered = Ready(); var release = Ready(); var claims = new ConcurrentQueue<string>();
        var handled = new ConcurrentQueue<string>();
        var run = Run(queue, (id, _) => { claims.Enqueue(id); return Task.FromResult<string?>(id); },
            async (id, _) => { handled.Enqueue(id); if (handled.Count == 4) entered.TrySetResult(); await release.Task; });
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal(4, claims.Count); Assert.Equal(4, handled.Count);
        }
        finally { release.TrySetResult(); }
        await run.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(8, claims.Count); Assert.Equal(8, handled.Count);
    }

    [Fact]
    public async Task HandlerFailureIsObservedWhileListenerIsIdle()
    {
        var entered = Ready(); var failed = Ready();
        var run = Run(Queue("r1"), (id, _) => Task.FromResult<string?>(id),
            (_, _) => { entered.TrySetResult(); return failed.Task; });
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        failed.SetException(new InvalidOperationException("fixed_handler_failure"));
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => run.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Equal("fixed_handler_failure", error.Message);
    }

    [Fact]
    public async Task TransportFailureDrainsAlreadyClaimedWorkWithoutCancellingIt()
    {
        var failed = Ready(); var release = Ready(); CancellationToken handlerToken = default;
        async IAsyncEnumerable<string> Source([EnumeratorCancellation] CancellationToken token = default)
        {
            yield return "r1";
            await Task.Yield(); failed.TrySetResult();
            throw new InvalidOperationException("fixed_transport_failure");
        }
        var run = FirebaseControlDispatch.RunAsync(Source(), (id, _) => Task.FromResult<string?>(id),
            (_, token) => { handlerToken = token; return release.Task; }, id => id, 4, CancellationToken.None);
        try
        {
            await failed.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.False(run.IsCompleted); Assert.False(handlerToken.IsCancellationRequested);
        }
        finally { release.TrySetResult(); }
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => run.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Equal("fixed_transport_failure", error.Message);
    }

    [Fact]
    public async Task HostCancellationReachesActiveHandlerAndIdleReceive()
    {
        using var stop = new CancellationTokenSource(); var entered = Ready(); var finished = Ready();
        var run = Run(Queue("r1"), (id, _) => Task.FromResult<string?>(id), async (_, token) =>
        {
            entered.TrySetResult();
            try { await Task.Delay(Timeout.Infinite, token); }
            finally { finished.TrySetResult(); }
        }, stop.Token);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5)); stop.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.True(finished.Task.IsCompleted);
    }

    [Theory]
    [InlineData("")]
    [InlineData("wrong/path")]
    [InlineData("wrong?query")]
    public async Task InvalidHintIsRejectedBeforeClaim(string id)
    {
        var called = false;
        await Assert.ThrowsAsync<InvalidOperationException>(() => Run(Queue(id),
            (_, _) => { called = true; return Task.FromResult<string?>(null); }, (_, _) => Task.CompletedTask));
        Assert.False(called);
    }

    [Fact]
    public async Task FailedClaimNeverInvokesHandler()
    {
        var called = false;
        await Assert.ThrowsAsync<InvalidOperationException>(() => Run(Queue("r1"),
            (_, _) => Task.FromException<string?>(new InvalidOperationException("claim_failed")),
            (_, _) => { called = true; return Task.CompletedTask; }));
        Assert.False(called);
    }

    [Fact]
    public async Task MismatchedClaimResponseNeverInvokesHandler()
    {
        var called = false;
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => Run(Queue("r1"),
            (_, _) => Task.FromResult<string?>("different-request"),
            (_, _) => { called = true; return Task.CompletedTask; }));
        Assert.Equal("firebaseControlClaimMismatch", error.Message);
        Assert.False(called);
    }
}
