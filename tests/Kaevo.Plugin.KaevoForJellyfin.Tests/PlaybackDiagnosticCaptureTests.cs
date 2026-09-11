using System.Text.Json;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class PlaybackDiagnosticCaptureTests
{
    private sealed class Clock : TimeProvider
    {
        internal long Milliseconds;
        internal int WallOffset;
        public override long TimestampFrequency => 1000;
        public override long GetTimestamp() => Milliseconds;
        public override DateTimeOffset GetUtcNow() => DateTimeOffset.FromUnixTimeMilliseconds(1_800_000_000_000 + Milliseconds + WallOffset * 1000L);
        internal long Expiry => GetUtcNow().ToUnixTimeSeconds() + 300;
    }
    [Fact]
    public void DisabledExpiredAndUnboundedWindowsNeverCapture()
    {
        var clock = new Clock(); var gate = new PlaybackDiagnosticCapture(clock);
        foreach (var expiry in new[] { 0L, clock.Expiry - 300, clock.Expiry + 1 })
            Assert.Null(gate.BeginCommand(expiry, "request-secret", _ => Assert.Fail("disabled capture emitted")));
        Assert.Null(gate.BeginMedia(clock.Expiry, "session", "request", _ => Assert.Fail(), 0));
    }
    [Fact]
    public void ClaimAndUpstreamSpansUseOneMonotonicOriginAndExcludeSecrets()
    {
        var clock = new Clock(); var gate = new PlaybackDiagnosticCapture(clock); var lines = new List<string>();
        var expiry = clock.Expiry; var start = gate.Timestamp; clock.Milliseconds = 25;
        gate.RememberClaim(expiry, "request-secret", start); clock.Milliseconds = 40;
        var command = gate.BeginCommand(expiry, "request-secret", lines.Add)!;
        clock.Milliseconds = 50; command.Mark(PlaybackDiagnosticStep.UpstreamRequest, PlaybackDiagnosticTrace.Resource("/Users/user-secret/Items/item-secret?Fields=UserData"));
        clock.Milliseconds = 125; command.Mark(PlaybackDiagnosticStep.UpstreamHeaders, PlaybackDiagnosticResource.Authority, 200);
        command.Fail(new HttpRequestException("token-secret /Media/path-secret")); command.Dispose(); command.Dispose();
        var line = Assert.Single(lines); Assert.DoesNotContain("secret", line); Assert.DoesNotContain("/Media/", line);
        using var json = JsonDocument.Parse(line); var root = json.RootElement;
        Assert.Equal(PlaybackDiagnosticCapture.Tag("request-secret"), root.GetProperty("request_tag").GetString());
        Assert.Equal("Http", root.GetProperty("outcome").GetString());
        Assert.Equal(new[] {25d,40,50,125,125}, root.GetProperty("points").EnumerateArray().Select(x => x.GetProperty("elapsed_ms").GetDouble()));
    }
    [Fact]
    public void OneCommandExactSessionAndSixteenMediaRequestsEvenUnderConcurrency()
    {
        var clock = new Clock(); var gate = new PlaybackDiagnosticCapture(clock); var expiry = clock.Expiry;
        var command = gate.BeginCommand(expiry, "one", _ => {})!;
        Assert.Null(gate.BeginCommand(expiry, "two", _ => {}));
        gate.BindSession(expiry, command, "session-one");
        Assert.Null(gate.BeginMedia(expiry, "session-two", "wrong", _ => Assert.Fail(), 0));
        var count = 0;
        Parallel.For(0, 200, i => { using var trace = gate.BeginMedia(expiry, "session-one", i.ToString(), _ => {}, 0); if (trace is not null) Interlocked.Increment(ref count); });
        Assert.Equal(16, count);
    }
    [Fact]
    public void RearmingCannotAttachAnOldCommandToNewWindow()
    {
        var clock = new Clock(); var gate = new PlaybackDiagnosticCapture(clock); var first = gate.BeginCommand(clock.Expiry, "first", _ => {})!;
        clock.Milliseconds = 1000; var expiry = clock.Expiry;
        var second = gate.BeginCommand(expiry, "second", _ => {})!;
        gate.BindSession(expiry, first, "old-session");
        Assert.Null(gate.BeginMedia(expiry, "old-session", "request", _ => {}, 0));
        gate.BindSession(expiry, second, "new-session");
        Assert.NotNull(gate.BeginMedia(expiry, "new-session", "request", _ => {}, 0));
    }
    [Fact]
    public void ExpiryAndMonotonicDurationEndCaptureDespiteClockRollback()
    {
        var clock = new Clock(); var gate = new PlaybackDiagnosticCapture(clock); var expiry = clock.Expiry;
        var trace = gate.BeginCommand(expiry, "request", _ => {})!; gate.BindSession(expiry, trace, "session");
        clock.Milliseconds = 301_000; clock.WallOffset = -200;
        Assert.Null(gate.BeginMedia(expiry, "session", "request", _ => {}, 0));
    }
    [Fact]
    public void DiagnosticSinkCannotFailPlaybackAndRepeatedPointsAreBounded()
    {
        var clock = new Clock(); var gate = new PlaybackDiagnosticCapture(clock); var calls = 0;
        var trace = gate.BeginCommand(clock.Expiry, "request", line => { calls++; using var json = JsonDocument.Parse(line); Assert.Equal(3, json.RootElement.GetProperty("points").GetArrayLength()); throw new IOException("sink failure"); })!;
        for (var i = 0; i < 10000; i++) trace.Mark(PlaybackDiagnosticStep.FirstBodySent);
        trace.Dispose(); trace.Dispose(); Assert.Equal(1, calls);
    }
}
