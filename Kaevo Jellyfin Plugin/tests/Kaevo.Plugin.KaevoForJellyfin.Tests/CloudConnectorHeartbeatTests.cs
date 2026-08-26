using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class CloudConnectorHeartbeatTests
{
    [Fact]
    public async Task HeartbeatScheduleContinuesWhileCommandWorkIsBlocked()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var firstHeartbeat = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var secondHeartbeat = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var heartbeatCount = 0;
        var blockedCommand = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        var schedule = KaevoCloudConnectorService.RunHeartbeatScheduleAsync(
            _ =>
            {
                var count = Interlocked.Increment(ref heartbeatCount);
                if (count == 1)
                {
                    firstHeartbeat.TrySetResult();
                }
                else if (count == 2)
                {
                    secondHeartbeat.TrySetResult();
                }
                return Task.CompletedTask;
            },
            TimeSpan.FromMilliseconds(10),
            cancellation.Token);

        await firstHeartbeat.Task.WaitAsync(TimeSpan.FromSeconds(1));
        Assert.False(blockedCommand.Task.IsCompleted);
        await secondHeartbeat.Task.WaitAsync(TimeSpan.FromSeconds(1));
        Assert.True(Volatile.Read(ref heartbeatCount) >= 2);

        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => schedule);
    }

    [Fact]
    public async Task HeartbeatScheduleStopsOnConfigurationCancellation()
    {
        using var cancellation = new CancellationTokenSource();
        var heartbeatObserved = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var schedule = KaevoCloudConnectorService.RunHeartbeatScheduleAsync(
            _ =>
            {
                heartbeatObserved.TrySetResult();
                return Task.CompletedTask;
            },
            TimeSpan.FromMinutes(1),
            cancellation.Token);

        await heartbeatObserved.Task.WaitAsync(TimeSpan.FromSeconds(1));
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => schedule);
    }
}
