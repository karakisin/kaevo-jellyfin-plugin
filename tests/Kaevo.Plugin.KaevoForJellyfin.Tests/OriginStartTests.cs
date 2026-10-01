using System.Collections.Concurrent;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;
using MediaBrowser.Controller.MediaEncoding;
using MediaBrowser.Model.Entities;
using MediaBrowser.Model.Session;

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

    [Fact]
    public async Task ResumePlaylistHintIsBoundToTheApprovedFullTimelineSession()
    {
        var owner = new KaevoOriginStart();
        var scope = Scope(ticks: 9_150_000_000);
        using var lifetime = new CancellationTokenSource();
        Assert.True(owner.TryStart(scope, Deadline,
            async (_, token) => { await Task.Delay(Timeout.Infinite, token); return Master; },
            (_, _) => Task.CompletedTask, () => Task.CompletedTask, _ => { }, lifetime.Token));
        var grant = Grant(scope);
        Assert.Contains("TIME-OFFSET=915,PRECISE=YES", owner.PreferResumeStart(grant, Master));
        Assert.Equal(Master, owner.PreferResumeStart(grant with { DeviceId = "other" }, Master));
        Assert.Equal(Master, owner.PreferResumeStart(grant with { ItemId = "other" }, Master));
        Assert.Equal(Master, owner.PreferResumeStart(grant with { PlaybackSessionId = "other" }, Master));
        Assert.Equal(Master, owner.PreferResumeStart(grant with { ConnectorId = "other" }, Master));
        Assert.Equal(Master, owner.PreferResumeStart(grant with { MediaSourceId = "other" }, Master));
        Assert.Equal(Master, owner.PreferResumeStart(grant with { Mode = "remux" }, Master));
        lifetime.Cancel();
        await Task.Delay(50);
        Assert.Equal(Master, owner.PreferResumeStart(grant, Master));
    }

    [Fact]
    public async Task RelativeCompactTimelineNeverReceivesSourceResumeOffset()
    {
        var owner = new KaevoOriginStart();
        var scope = Scope(ticks: 9_150_000_000) with { CompactRuntimeTicks = 90_000_000_000 };
        using var lifetime = new CancellationTokenSource();
        Assert.True(owner.TryStart(scope, Deadline, Playlist,
            async (_, token) => await Task.Delay(Timeout.Infinite, token),
            () => Task.CompletedTask, _ => { }, lifetime.Token));
        Assert.Equal(Master, owner.PreferResumeStart(Grant(scope), Master));
        lifetime.Cancel();
        await Task.Delay(50);
    }

    [Theory]
    [InlineData("1.ts", true)]
    [InlineData("2.ts", true)]
    [InlineData("-1.ts", false)]
    [InlineData("main.m3u8", false)]
    [InlineData("2.mp4", false)]
    public void DeliveryRequiresRealScopedMedia(string file, bool expected)
    {
        var scope = Scope();
        Assert.Equal(expected, scope.IsDeliveredMediaSegment($"/Videos/{Item}/hls1/main/{file}?playSessionId=play-session&deviceId=device&mediaSourceId=source"));
        Assert.False(scope.IsDeliveredMediaSegment($"/Videos/{Item}/hls1/main/{file}?playSessionId=other"));
    }

    [Fact]
    public async Task NeighboringSegmentPreventsTimeoutFromKillingActivePlayback()
    {
        var owner = new KaevoOriginStart(); var scope = Scope();
        using var lifetime = new CancellationTokenSource();
        var entered = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        var stopped = false;
        Assert.True(owner.TryStart(scope, Deadline, Playlist,
            (path, _) => { entered.SetResult(path); return Task.CompletedTask; },
            () => { stopped = true; return Task.CompletedTask; }, _ => { }, lifetime.Token));
        var path = await entered.Task.WaitAsync(TimeSpan.FromSeconds(2));
        Assert.Contains("/1.ts?", path);
        owner.Delivered(Grant(scope), path.Replace("/1.ts?", "/2.ts?"));
        lifetime.Cancel();
        await Task.Delay(50);
        Assert.False(stopped);
    }

    [Fact]
    public void CompactSegmentMatchesRelayRenditionAndExactResume()
    {
        var scope = Scope(ticks: 123_456_789) with { CompactRuntimeTicks = 90_000_000_000 };
        var path = scope.CompactFirstSegment();
        Assert.StartsWith($"/Videos/{Item}/hls1/main/0.ts?", path);
        var query = path.Split('?')[1].Split('&').Select(p => p.Split('=', 2))
            .ToDictionary(p => p[0], p => p[1]);
        Assert.Equal("123456789", query["runtimeTicks"]);
        Assert.Equal("20000000", query["actualSegmentLengthTicks"]);
        Assert.Equal("5744000", query["videoBitRate"]);
        Assert.Equal("2", query["segmentLength"]);
        Assert.Equal("1", query["audioStreamIndex"]);
        Assert.Equal("play-session", query["playSessionId"]);
        Assert.False(query.ContainsKey("StartTimeTicks"));
        Assert.True(scope.MatchesCompactPosition(path));
        Assert.False(scope.MatchesCompactPosition(path.Replace("123456789", "123456788")));
        Assert.False(scope.MatchesCompactPosition(path + "&runtimeTicks=123456789"));
        var tail = scope with { PositionTicks = scope.CompactRuntimeTicks.Value - 123 };
        Assert.Contains("actualSegmentLengthTicks=123", tail.CompactFirstSegment());
        Assert.Throws<InvalidOperationException>(() => (scope with { CompactRuntimeTicks = 10 }).CompactFirstSegment());
        Assert.Throws<InvalidOperationException>(() => (scope with { PositionTicks = -1 }).CompactFirstSegment());
    }

    [Fact]
    public async Task CompactPlayerSeekTakesOwnershipOfItsExactSession()
    {
        var owner = new KaevoOriginStart();
        var scope = Scope() with { CompactRuntimeTicks = 90_000_000_000 };
        using var lifetime = new CancellationTokenSource();
        var entered = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        var stopped = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Assert.True(owner.TryStart(scope, Deadline,
            (_, _) => throw new Exception("Compact must not request full-timeline playlists"),
            (path, _) => { entered.SetResult(path); return Task.CompletedTask; },
            () => { stopped.TrySetResult(); return Task.CompletedTask; }, _ => { }, lifetime.Token));
        var path = await entered.Task.WaitAsync(TimeSpan.FromSeconds(2));
        owner.Delivered(Grant(scope), path.Replace("runtimeTicks=45000000", "runtimeTicks=0"));
        lifetime.Cancel();
        await Task.Delay(50);
        Assert.False(stopped.Task.IsCompleted);
    }

    [Fact]
    public async Task CompactExactHandoffPreservesTheRealPlayerJob()
    {
        var owner = new KaevoOriginStart();
        var scope = Scope() with { CompactRuntimeTicks = 90_000_000_000 };
        using var lifetime = new CancellationTokenSource();
        var entered = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        var completed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var stopped = false;
        Assert.True(owner.TryStart(scope, Deadline, (_, _) => throw new Exception("No playlist"),
            (path, _) => { entered.SetResult(path); return Task.CompletedTask; },
            () => { stopped = true; return Task.CompletedTask; },
            stage => { if (stage == "segment_ready") completed.TrySetResult(); }, lifetime.Token));
        var path = await entered.Task.WaitAsync(TimeSpan.FromSeconds(2));
        owner.Delivered(Grant(scope), path);
        await completed.Task.WaitAsync(TimeSpan.FromSeconds(2));
        lifetime.Cancel();
        await Task.Delay(30);
        Assert.False(stopped);
    }

    private const string RemuxMedia = "#EXTM3U\n#EXT-X-MAP:URI=\"hls1/main/-1.mp4?runtimeTicks=0&actualSegmentLengthTicks=0\"\n#EXTINF:2,\nhls1/main/0.mp4\n#EXTINF:2,\nhls1/main/1.mp4\n#EXTINF:2,\nhls1/main/2.mp4\n#EXT-X-ENDLIST\n";

    [Fact]
    public void RemuxStartsAtResumeSegmentAndPreservesSourceVideo()
    {
        var scope = Scope() with { Mode = "remux" };
        var query = scope.Rendition();
        Assert.Equal("h264,hevc", query["videoCodec"]);
        Assert.Equal("39808000", query["videoBitRate"]);
        Assert.Equal("true", query["allowVideoStreamCopy"]);
        Assert.Equal("true", query["allowAudioStreamCopy"]);
        Assert.Equal("true", query["enableAutoStreamCopy"]);
        Assert.Equal("mp4", query["segmentContainer"]);
        Assert.Equal("2", query["segmentLength"]);
        Assert.Equal("1", query["minSegments"]);
        Assert.False(query.ContainsKey("maxWidth"));
        Assert.False(query.ContainsKey("maxHeight"));
        Assert.Contains("/2.mp4?", scope.ResumeSegment(RemuxMedia, scope.MasterPath));
    }

    [Theory]
    [InlineData("remux", "aac", 128000, true)]
    [InlineData("remux", "dts", 128000, false)]
    [InlineData("remux", "aac", 320000, false)]
    [InlineData("transcode", "aac", 128000, false)]
    public void ActualJellyfinAudioCopyDecisionHonorsRenditionAndCompatibility(
        string mode, string codec, int bitrate, bool expectedCopy)
    {
        var query = (Scope() with { Mode = mode }).Rendition();
        var request = new BaseEncodingJobOptions {
            AllowAudioStreamCopy = bool.Parse(query["allowAudioStreamCopy"]),
            EnableAutoStreamCopy = bool.Parse(query["enableAutoStreamCopy"]),
            AudioBitRate = int.Parse(query["audioBitRate"])
        };
        var job = new EncodingJobInfo(TranscodingJobType.Hls) { BaseRequest = request };
        var audio = new MediaStream { Codec = codec, Channels = 2, SampleRate = 44100, BitRate = bitrate };
        // This provider method is pure; no encoder process or server services are used.
        var helper = new EncodingHelper(null!, null!, null!, null!, null!);
        Assert.Equal(expectedCopy, helper.CanStreamCopyAudio(job, audio, query["audioCodec"].Split(',')));
        request.EnableAutoStreamCopy = false;
        Assert.False(helper.CanStreamCopyAudio(job, audio, query["audioCodec"].Split(',')));
    }

    [Theory]
    [InlineData("https://evil.invalid/init.mp4")]
    [InlineData("//evil.invalid/init.mp4")]
    [InlineData("../other/init.mp4")]
    [InlineData("hls1/main/-1.mp4?playSessionId=other")]
    [InlineData("hls1/main/-1.mp4?mediaSourceId=other")]
    [InlineData("hls1/main/-1.mp4?token=secret")]
    public void RemuxInitializationMustStayInsideTheExactPlaybackScope(string map)
    {
        var scope = Scope() with { Mode = "remux" };
        Assert.Throws<InvalidOperationException>(() => scope.ResumeSegment(
            RemuxMedia.Replace("hls1/main/-1.mp4?runtimeTicks=0&actualSegmentLengthTicks=0", map), scope.MasterPath));
    }

    [Fact]
    public void RemuxRejectsAmbiguousMapsAndEncryptedOrRangedMedia()
    {
        var scope = Scope() with { Mode = "remux" };
        foreach (var tag in new[] { "#EXT-X-MAP:URI=\"hls1/main/-1.mp4\"", "#EXT-X-KEY:METHOD=AES-128,URI=\"key\"", "#EXT-X-BYTERANGE:100@0", "#EXT-X-DISCONTINUITY" })
            Assert.Throws<InvalidOperationException>(() => scope.ResumeSegment(RemuxMedia.Replace("#EXTM3U", "#EXTM3U\n" + tag), scope.MasterPath));
    }

    [Fact]
    public async Task RemuxDeliveryPromotesTheExactPreparedSegment()
    {
        var owner = new KaevoOriginStart(); var scope = Scope() with { Mode = "remux" };
        using var lifetime = new CancellationTokenSource();
        var entered = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        var ready = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var stopped = false;
        Assert.True(owner.TryStart(scope, Deadline,
            (path, _) => Task.FromResult(path.Contains("master.m3u8") ? Master : RemuxMedia),
            (path, _) => { entered.SetResult(path); return Task.CompletedTask; },
            () => { stopped = true; return Task.CompletedTask; },
            stage => { if (stage == "segment_ready") ready.TrySetResult(); }, lifetime.Token));
        var path = await entered.Task.WaitAsync(TimeSpan.FromSeconds(2));
        owner.Delivered(Grant(scope) with { Mode = "remux" }, path);
        await ready.Task.WaitAsync(TimeSpan.FromSeconds(2));
        lifetime.Cancel();
        Assert.False(stopped);
    }

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
    public void TranscodeWarmupMatchesNativeDefaultRenditionAndKeepsHardwareSelection()
    {
        var query = Scope().Rendition();
        Assert.Equal("h264", query["videoCodec"]);
        Assert.Equal("5744000", query["videoBitRate"]);
        Assert.Equal("192000", query["audioBitRate"]);
        Assert.Equal("1280", query["maxWidth"]);
        Assert.Equal("720", query["maxHeight"]);
        Assert.Equal("2", query["segmentLength"]);
        Assert.Equal("ts", query["segmentContainer"]);
        Assert.DoesNotContain(query.Keys, key => key.Contains("encoder", StringComparison.OrdinalIgnoreCase));
    }

    [Theory]
    [InlineData(1_000_000, "808000")]
    [InlineData(6_000_000, "5744000")]
    [InlineData(40_000_000, "5744000")]
    public void TranscodeWarmupRespectsTheSignedBitrateCeiling(int maximum, string videoBitrate)
    {
        var query = (Scope() with { MaximumBitrate = maximum }).Rendition();
        Assert.Equal(videoBitrate, query["videoBitRate"]);
    }

    [Fact]
    public async Task NativeTwoSecondResumeDeliveryPromotesWarmupWithoutStoppingThePlayer()
    {
        const string nativeMedia = "#EXTM3U\n#EXT-X-PLAYLIST-TYPE:VOD\n#EXTINF:2,\nhls1/main/0.ts\n#EXTINF:2,\nhls1/main/1.ts\n#EXTINF:2,\nhls1/main/2.ts\n#EXT-X-ENDLIST\n";
        var scope = Scope();
        var owner = new KaevoOriginStart();
        var ready = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        var disposed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var stopped = false;
        Assert.True(owner.TryStart(scope, Deadline,
            (path, _) => Task.FromResult(path.Contains("master.m3u8") ? Master : nativeMedia),
            (path, _) => { ready.SetResult(path); return Task.CompletedTask; },
            () => { stopped = true; return Task.CompletedTask; }, _ => { }, default,
            observationResource: new TestLease(() => disposed.SetResult())));
        var path = await ready.Task.WaitAsync(TimeSpan.FromSeconds(2));
        Assert.Contains("/2.ts?", path);
        owner.Delivered(Grant(scope), path);
        await disposed.Task.WaitAsync(TimeSpan.FromSeconds(2));
        Assert.False(stopped);
    }


    [Theory]
    [InlineData("transcode", 72_000_000_000L, true)]
    [InlineData("transcode", 72_000_000_001L, false)]
    [InlineData("transcode", 0L, false)]
    [InlineData("remux", 108_000_000_000L, true)]
    [InlineData("direct_play", 36_000_000_000L, false)]
    public void CompactLongTranscodesDoNotStartAnIncompatibleFullTimelineWarmup(string mode, long ticks, bool expected)
        => Assert.Equal(expected, PlaybackOriginScope.CanWarmNativeRendition(mode, ticks));

}
