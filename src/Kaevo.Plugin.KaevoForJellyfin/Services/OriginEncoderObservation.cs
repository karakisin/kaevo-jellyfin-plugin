using System.Globalization;
using MediaBrowser.Controller.MediaEncoding;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

// Read-only samples of the one already-authorized Jellyfin job. Never opens the
// source movie, consumes FFmpeg output, launches a process or changes job state.
internal sealed record OriginEncoderSnapshot(bool ProcessStarted, bool ProgressReported,
    bool SegmentExists, bool NextSegmentExists, bool Exited);

internal static class OriginEncoderObservation
{
    internal const int MaximumSamples = 300;
    internal static readonly TimeSpan Interval = TimeSpan.FromMilliseconds(100);

    internal static OriginEncoderSnapshot? Read(TranscodingJob? job, PlaybackOriginScope scope, int index)
    {
        if (job is null || job.Type != TranscodingJobType.Hls || index < 0 || index == int.MaxValue
            || !string.Equals(job.PlaySessionId, scope.PlaySessionId, StringComparison.Ordinal)
            || !string.Equals(job.DeviceId, scope.DeviceId, StringComparison.Ordinal)
            || !string.Equals(job.MediaSource?.Id, scope.MediaSourceId, StringComparison.Ordinal)) return null;
        var path = job.Path;
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path)
            || !path.EndsWith(".m3u8", StringComparison.Ordinal)) return null;
        // Jellyfin's HLS controller uses this exact job-owned basename + index.
        // Only existence is observed; partially written files are never served.
        var basename = Path.Combine(Path.GetDirectoryName(path)!, Path.GetFileNameWithoutExtension(path));
        var started = false;
        try { started = job.Process is not null && job.Process.Id > 0; }
        catch (InvalidOperationException) { } // Not started yet or concurrently disposed.
        return new OriginEncoderSnapshot(started,
            job.Framerate is > 0 || job.TranscodingPositionTicks is > 0,
            File.Exists(basename + index.ToString(CultureInfo.InvariantCulture) + ".ts"),
            File.Exists(basename + (index + 1).ToString(CultureInfo.InvariantCulture) + ".ts"), job.HasExited);
    }

    internal static async Task ObserveAsync(Func<OriginEncoderSnapshot?> read, PlaybackDiagnosticTrace trace,
        CancellationToken cancellationToken)
    {
        try
        {
            for (var sample = 0; sample < MaximumSamples && !cancellationToken.IsCancellationRequested; sample++)
            {
                var state = read();
                if (state is not null)
                {
                    trace.Mark(PlaybackDiagnosticStep.EncoderJobObserved);
                    if (state.ProcessStarted) trace.Mark(PlaybackDiagnosticStep.EncoderProcessObserved);
                    if (state.ProgressReported) trace.Mark(PlaybackDiagnosticStep.EncoderProgressObserved);
                    if (state.SegmentExists) trace.Mark(PlaybackDiagnosticStep.SegmentFileObserved);
                    if (state.NextSegmentExists) trace.Mark(PlaybackDiagnosticStep.NextSegmentFileObserved);
                    if (state.Exited) { trace.Mark(PlaybackDiagnosticStep.EncoderExited); return; }
                    if (state.SegmentExists && state.NextSegmentExists) return;
                }
                await Task.Delay(Interval, cancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception) { trace.Mark(PlaybackDiagnosticStep.ObservationUnavailable); }
    }
}
