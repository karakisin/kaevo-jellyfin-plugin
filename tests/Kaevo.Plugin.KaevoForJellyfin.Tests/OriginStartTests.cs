using System.Collections.Concurrent;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class OriginStartTests
{
    private const string Item = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    private static PlaybackOriginScope Scope(string session = "play-session", long ticks = 45_000_000)
        => new("connector", "device", Item, "source", session, 40_000_000, 1, ticks);
    private const string Master = "#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=12000000\nmain.m3u8\n";
    private const string Media = "#EXTM3U\n#EXT-X-PLAYLIST-TYPE:VOD\n#EXTINF:4,\nhls1/main/0.ts\n#EXTINF:4,\nhls1/main/1.ts\n#EXTINF:2,\nhls1/main/2.ts\n#EXT-X-ENDLIST\n";
    private static Task<string> Playlist(string path, CancellationToken _) => Task.FromResult(path.Contains("master.m3u8") ? Master : Media);
    private static long Deadline => DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 20;
    private static PlaybackGrant Grant(PlaybackOriginScope scope) => new(scope.ConnectorId, scope.DeviceId, scope.ItemId,
        scope.MediaSourceId, scope.PlaySessionId, "transcode", scope.MaximumBitrate, Deadline);

    [Theory]
    [InlineData(0, "0.ts")]
    [InlineData(39_999_999, "0.ts")]
    [InlineData(40_000_000, "1.ts")]
    [InlineData(99_999_999, "2.ts")]
    public void ExactTimelineSelectsTheResumedSegment(long ticks, string expected)
    {
        var scope = Scope(ticks: ticks);
        var media = scope.FirstVariant(Master, scope.MasterPath);
        var segment = scope.ResumeSegment(Media, media);
        Assert.Contains("/" + expected + "?", segment);
        Assert.Contains("playSessionId=play-session", segment);
        Assert.Contains("deviceId=device", segment);
        Assert.Contains("mediaSourceId=source", segment);
    }

    [Theory]
    [InlineData("https://evil.invalid/a.m3u8")]
    [InlineData("//evil.invalid/a.m3u8")]
    [InlineData("../other/main.m3u8")]
    [InlineData("main.m3u8#fragment")]
    [InlineData("main.m3u8?playSessionId=other")]
    [InlineData("main.m3u8?deviceId=other")]
    [InlineData("main.m3u8?mediaSourceId=other")]
    [InlineData("main.m3u8?videoBitRate=90000000")]
    [InlineData("main.m3u8?token=secret")]
    [InlineData("main.m3u8?a=1&A=2")]
    public void ForeignOrAmbiguousChildNeverReachesProvider(string child)
        => Assert.Throws<InvalidOperationException>(() => Scope().FirstVariant(Master.Replace("main.m3u8", child), Scope().MasterPath));

    [Theory]
    [InlineData("#EXT-X-KEY:METHOD=AES-128,URI=\"key\"")]
    [InlineData("#EXT-X-MAP:URI=\"init.mp4\"")]
    [InlineData("#EXT-X-DISCONTINUITY")]
    [InlineData("#EXT-X-BYTERANGE:100@0")]
    public void UnsupportedTimelineCannotStartAnIncorrectEncoder(string tag)
        => Assert.Throws<InvalidOperationException>(() => Scope().ResumeSegment(Media.Replace("#EXTM3U", "#EXTM3U\n" + tag), Scope().MasterPath));

    [Fact]
    public void MissingDurationAndPositionBeyondEndAreRejected()
    {
        Assert.Throws<InvalidOperationException>(() => Scope().ResumeSegment(Media.Replace("#EXTINF:4,\n", ""), Scope().MasterPath));
        Assert.Throws<InvalidOperationException>(() => Scope(ticks: 100_000_000).ResumeSegment(Media, Scope().MasterPath));
    }

    [Fact]
    public async Task NativeBodyTakesOverTheSameJobWithoutWaitingForLocalProbe()
    {
        var owner = new KaevoOriginStart(); var scope = Scope();
        using var lifetime = new CancellationTokenSource();
        var segmentEntered = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        var prefix = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var finished = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var stops = 0;
        Assert.True(owner.TryStart(scope, Deadline, Playlist, async (path, token) =>
        { segmentEntered.SetResult(path); await prefix.Task.WaitAsync(token); },
            () => { Interlocked.Increment(ref stops); return Task.CompletedTask; },
            stage => { if (stage == "segment_ready") finished.TrySetResult(); }, lifetime.Token));
        var path = await segmentEntered.Task.WaitAsync(TimeSpan.FromSeconds(2));
        owner.Delivered(Grant(scope), path);
        prefix.SetResult();
        await finished.Task.WaitAsync(TimeSpan.FromSeconds(2));
        lifetime.Cancel();
        Assert.Equal(0, stops);
    }

    [Fact]
    public async Task WrongScopeAndManifestDoNotPreventAbandonedJobCleanup()
    {
        var owner = new KaevoOriginStart(); var scope = Scope();
        using var lifetime = new CancellationTokenSource();
        var entered = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        var stopped = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Assert.True(owner.TryStart(scope, Deadline, Playlist, async (path, token) =>
        { entered.SetResult(path); await Task.Delay(Timeout.InfiniteTimeSpan, token); },
            () => { stopped.SetResult(); return Task.CompletedTask; }, _ => { }, lifetime.Token));
        var segment = await entered.Task.WaitAsync(TimeSpan.FromSeconds(2));
        owner.Delivered(Grant(scope) with { DeviceId = "other" }, segment);
        owner.Delivered(Grant(scope), scope.MasterPath);
        lifetime.Cancel();
        await stopped.Task.WaitAsync(TimeSpan.FromSeconds(2));
    }

    [Fact]
    public async Task DuplicateAndCapacityOverflowCannotLaunchMoreWork()
    {
        var owner = new KaevoOriginStart(); using var lifetime = new CancellationTokenSource();
        var stops = new ConcurrentBag<string>();
        var finished = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        bool Start(string session) => owner.TryStart(Scope(session), Deadline,
            async (_, token) => { await Task.Delay(Timeout.InfiniteTimeSpan, token); return ""; },
            (_, _) => throw new Exception("Unexpected media"),
            () => { stops.Add(session); if (stops.Count == 2) finished.TrySetResult(); return Task.CompletedTask; }, _ => { }, lifetime.Token);
        Assert.True(Start("one")); Assert.False(Start("one"));
        Assert.True(Start("two")); Assert.False(Start("three"));
        lifetime.Cancel(); await finished.Task.WaitAsync(TimeSpan.FromSeconds(2));
        Assert.Equal(new[] { "one", "two" }, stops.OrderBy(value => value));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(31)]
    public void ExpiredOrExtendedPermissionCannotBegin(int seconds)
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1000);
        Assert.False(new KaevoOriginStart().TryStart(Scope(), 1000 + seconds,
            (_, _) => throw new Exception("No reads allowed"), (_, _) => throw new Exception(),
            () => throw new Exception(), _ => { }, default, now));
    }

    [Fact]
    public async Task DisabledCaptureDoesNotReadEncoderAndRejectedAdmissionDoesNotOpenCapture()
    {
        var owner = new KaevoOriginStart(); using var lifetime = new CancellationTokenSource();
        var stopped = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var captures = 0;
        Assert.True(owner.TryStart(Scope(), Deadline, async (_, token) =>
        { await Task.Delay(Timeout.InfiniteTimeSpan, token); return ""; }, (_, _) => Task.CompletedTask,
            () => { stopped.TrySetResult(); return Task.CompletedTask; }, _ => {}, lifetime.Token,
            beginCapture: () => { captures++; return null; }, snapshot: _ => throw new Exception("disabled")));
        Assert.False(owner.TryStart(Scope(), Deadline, Playlist, (_, _) => Task.CompletedTask,
            () => Task.CompletedTask, _ => {}, lifetime.Token,
            beginCapture: () => throw new Exception("duplicate capture")));
        Assert.Equal(1, captures);
        lifetime.Cancel(); await stopped.Task.WaitAsync(TimeSpan.FromSeconds(2));
    }

    [Fact]
    public async Task CaptureCreationFailureStillCleansUpTheAdmittedJob()
    {
        var stopped = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Assert.True(new KaevoOriginStart().TryStart(Scope(), Deadline,
            (_, _) => throw new InvalidOperationException("origin unavailable"), (_, _) => Task.CompletedTask,
            () => { stopped.TrySetResult(); return Task.CompletedTask; }, _ => {}, default,
            beginCapture: () => throw new IOException("capture unavailable")));
        await stopped.Task.WaitAsync(TimeSpan.FromSeconds(2));
    }

    [Fact]
    public async Task HardwarePlanLeaseIsOnlyOpenedForAdmissionAndReleasedAfterCancelledJobCleanup()
    {
        var owner = new KaevoOriginStart(); using var lifetime = new CancellationTokenSource();
        var released = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var stopped = false; var opened = 0;
        Func<IDisposable?> plan = () => { opened++; return new TestLease(() => { Assert.True(stopped); released.SetResult(); }); };
        Assert.True(owner.TryStart(Scope(), Deadline, async (_, token) =>
        { await Task.Delay(Timeout.InfiniteTimeSpan, token); return ""; }, (_, _) => Task.CompletedTask,
            () => { stopped = true; return Task.CompletedTask; }, _ => { }, lifetime.Token, beginProducerPlan: plan));
        Assert.False(owner.TryStart(Scope(), Deadline, Playlist, (_, _) => Task.CompletedTask,
            () => Task.CompletedTask, _ => { }, lifetime.Token, beginProducerPlan: plan));
        Assert.Equal(1, opened);
        lifetime.Cancel(); await released.Task.WaitAsync(TimeSpan.FromSeconds(2));
    }

    [Fact]
    public async Task HardwarePlanFailureStillUsesOriginalOriginAndCleansUp()
    {
        var read = false; var stopped = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Assert.True(new KaevoOriginStart().TryStart(Scope(), Deadline,
            (_, _) => { read = true; throw new IOException("original read failed"); }, (_, _) => Task.CompletedTask,
            () => { stopped.SetResult(); return Task.CompletedTask; }, _ => { }, default,
            beginProducerPlan: () => throw new IOException("planner unavailable")));
        await stopped.Task.WaitAsync(TimeSpan.FromSeconds(2)); Assert.True(read);
    }

    private sealed class TestLease(Action release) : IDisposable { public void Dispose() => release(); }

    [Fact]
    public void RecipeKeepsExistingQualityAndConfiguredHardwareSelection()
    {
        var query = Scope().Rendition();
        Assert.Equal("h264", query["videoCodec"]);
        Assert.Equal("11808000", query["videoBitRate"]);
        Assert.Equal("192000", query["audioBitRate"]);
        Assert.Equal("1080", query["maxHeight"]);
        Assert.Equal("4", query["segmentLength"]);
        Assert.Equal("ts", query["segmentContainer"]);
        Assert.DoesNotContain(query.Keys, key => key.Contains("encoder", StringComparison.OrdinalIgnoreCase));
    }
}
