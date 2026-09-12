using System.Diagnostics;
using System.Text.Json;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using MediaBrowser.Controller.MediaEncoding;
using MediaBrowser.Model.Dto;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class OriginEncoderObservationTests
{
    private static readonly PlaybackOriginScope Scope = new("connector", "device", "item", "source", "session", 40_000_000, 1, 45_000_000);
    private static TranscodingJob Job(string path) => new(NullLogger<TranscodingJob>.Instance)
    { Type = TranscodingJobType.Hls, Path = path, DeviceId = Scope.DeviceId, PlaySessionId = Scope.PlaySessionId,
      MediaSource = new MediaSourceInfo { Id = Scope.MediaSourceId } };

    [Theory]
    [InlineData("device")]
    [InlineData("session")]
    [InlineData("source")]
    [InlineData("progressive")]
    [InlineData("relative")]
    [InlineData("extension")]
    public void UnrelatedOrUnsupportedJobCannotProduceObservations(string mismatch)
    {
        using var job = Job(Path.Combine(Path.GetTempPath(), "encoder-test.m3u8"));
        switch (mismatch)
        {
            case "device": job.DeviceId = "other"; break;
            case "session": job.PlaySessionId = "other"; break;
            case "source": job.MediaSource!.Id = "other"; break;
            case "progressive": job.Type = TranscodingJobType.Progressive; break;
            case "relative": job.Path = "encoder-test.m3u8"; break;
            case "extension": job.Path += ".mp4"; break;
        }
        Assert.Null(OriginEncoderObservation.Read(job, Scope, 1));
    }

    [Fact]
    public void ReadsOnlyExactExistingJobAndResumedSegmentNamesWithoutChangingIt()
    {
        var dir = Path.Combine(Path.GetTempPath(), "kaevo-origin-observation-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            using var process = Process.GetCurrentProcess();
            using var job = Job(Path.Combine(dir, "exact.m3u8"));
            job.Process = process; job.Framerate = 72;
            // Adjacent/unrelated output must not count as the requested segment.
            File.WriteAllText(Path.Combine(dir, "exact0.ts"), "previous");
            File.WriteAllText(Path.Combine(dir, "other1.ts"), "other job");
            var before = OriginEncoderObservation.Read(job, Scope, 1)!;
            Assert.True(before.ProcessStarted); Assert.True(before.ProgressReported);
            Assert.False(before.SegmentExists); Assert.False(before.NextSegmentExists);
            File.WriteAllText(Path.Combine(dir, "exact1.ts"), "first");
            File.WriteAllText(Path.Combine(dir, "exact2.ts"), "next");
            var after = OriginEncoderObservation.Read(job, Scope, 1)!;
            Assert.True(after.SegmentExists); Assert.True(after.NextSegmentExists);
            Assert.Equal(72, job.Framerate); Assert.Equal(0, job.ActiveRequestCount);
            Assert.Null(job.DownloadPositionTicks); Assert.False(job.HasExited);
            Assert.Null(OriginEncoderObservation.Read(job, Scope, -1));
            Assert.Null(OriginEncoderObservation.Read(job, Scope, int.MaxValue));
            Assert.Equal("first", File.ReadAllText(Path.Combine(dir, "exact1.ts")));
            job.Process = null; // The test never owns or stops the runner's process.
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public async Task ObservesPhasesOnceAndStopsWhenBothFilesExist()
    {
        var lines = new List<string>(); var samples = 0;
        var trace = new PlaybackDiagnosticTrace(TimeProvider.System, "origin", "opaque-tag", lines.Add, TimeProvider.System.GetTimestamp());
        await OriginEncoderObservation.ObserveAsync(() => ++samples switch
        {
            1 => null,
            2 => new(false, false, false, false, false),
            3 => new(true, true, true, false, false),
            _ => new(true, true, true, true, false)
        }, trace, CancellationToken.None);
        trace.Dispose();
        Assert.Equal(4, samples);
        using var json = JsonDocument.Parse(Assert.Single(lines));
        var points = json.RootElement.GetProperty("points").EnumerateArray().Select(x => x.GetProperty("step").GetString());
        Assert.Equal(new[] { "EncoderJobObserved", "EncoderProcessObserved", "EncoderProgressObserved", "SegmentFileObserved", "NextSegmentFileObserved", "Finished" }, points);
    }

    [Fact]
    public async Task CancellationAndReadErrorsNeverFailPlaybackOrLeakRawErrors()
    {
        var lines = new List<string>();
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        var trace = new PlaybackDiagnosticTrace(TimeProvider.System, "origin", "tag", lines.Add, TimeProvider.System.GetTimestamp());
        await OriginEncoderObservation.ObserveAsync(() => throw new Exception("must not run"), trace, cancelled.Token);
        await OriginEncoderObservation.ObserveAsync(() => throw new IOException("token-secret /Media/private"), trace, default);
        trace.Dispose();
        var text = Assert.Single(lines);
        Assert.DoesNotContain("secret", text); Assert.DoesNotContain("/Media", text);
        Assert.Contains("ObservationUnavailable", text);
    }
}
