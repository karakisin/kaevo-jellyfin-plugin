using MediaBrowser.Controller.MediaEncoding;
using MediaBrowser.Controller.Streaming;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

// All Jellyfin lifecycle methods remain delegated to its original singleton.
// A short-lived, locally registered exact Kaevo scope is required to change a
// startup plan. Query strings/client names cannot opt other clients into it.
internal sealed class KaevoHardwareTranscodeManager(ITranscodeManager inner, IMediaEncoder? mediaEncoder = null, ILogger<KaevoHardwareTranscodeManager>? logger = null) : ITranscodeManager
{
    private sealed record Admission(PlaybackOriginScope Scope, Guid User, long Deadline,
        CancellationToken Lifetime, Action Applied);
    private readonly KaevoValidatedTransportProbe _probe = new();
    private readonly object _gate = new();
    private readonly Dictionary<string, Admission> _admissions = new(StringComparer.Ordinal);

    internal IDisposable? Admit(PlaybackOriginScope scope, string userId, long deadline,
        CancellationToken lifetime, Action applied)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (!Guid.TryParse(userId, out var user) || user == Guid.Empty || lifetime.IsCancellationRequested
            || deadline <= now || deadline > now + 30) return null;
        var entry = new Admission(scope, user, deadline, lifetime, applied);
        lock (_gate)
        {
            foreach (var key in _admissions.Where(p => p.Value.Deadline <= now || p.Value.Lifetime.IsCancellationRequested)
                .Select(p => p.Key).ToArray()) _admissions.Remove(key);
            if (_admissions.Count >= 8 || !_admissions.TryAdd(scope.PlaySessionId, entry)) return null;
        }
        return new Lease(() =>
        {
            lock (_gate)
                if (_admissions.TryGetValue(scope.PlaySessionId, out var current) && ReferenceEquals(current, entry))
                    _admissions.Remove(scope.PlaySessionId);
        });
    }

    // Compact HLS starts only when the real player requests its first segment.
    // Retain the exact, signed Play admission until that start or its deadline;
    // this does not start an encoder or substitute a full-timeline warm-up.
    internal bool AdmitPlayerStart(PlaybackOriginScope scope, string userId, long deadline,
        CancellationToken lifetime, Action applied)
    {
        var lease = Admit(scope, userId, deadline, lifetime, applied);
        if (lease is null) return false;
        _ = ReleasePlayerStartAsync(lease, deadline, lifetime);
        return true;
    }

    private static async Task ReleasePlayerStartAsync(IDisposable lease, long deadline, CancellationToken lifetime)
    {
        using (lease)
        {
            var remaining = DateTimeOffset.FromUnixTimeSeconds(deadline) - DateTimeOffset.UtcNow;
            if (remaining <= TimeSpan.Zero) return;
            try { await Task.Delay(remaining, lifetime).ConfigureAwait(false); }
            catch (OperationCanceledException) { }
        }
    }

    internal string Plan(StreamState state, string command, Guid user, TranscodingJobType type, bool linux)
    {
        if (!linux || type != TranscodingJobType.Hls || state.Request is null || state.MediaSource is null) return command;
        Admission? admission;
        lock (_gate)
        {
            var session = state.Request.PlaySessionId;
            if (string.IsNullOrEmpty(session) || !_admissions.TryGetValue(session, out admission)) return command;
            var scope = admission.Scope;
            if (admission.Deadline <= DateTimeOffset.UtcNow.ToUnixTimeSeconds() || admission.Lifetime.IsCancellationRequested
                || admission.User != user || state.Request.DeviceId != scope.DeviceId
                || state.MediaSource.Id != scope.MediaSourceId || state.Request.MediaSourceId != scope.MediaSourceId
                || !Guid.TryParse(scope.ItemId, out var item) || item != state.Request.Id) return command;
            _admissions.Remove(session); // One actual process start only; no reusable privilege.
        }
        var plan = KaevoHardwareDependencyPlan.WithoutUnusedOpenCl(command);
        if (plan is null) return command;
        try { admission.Applied(); } catch { } // Optional diagnostics cannot prevent playback.
        return plan;
    }

    public async Task<TranscodingJob> StartFfMpeg(StreamState state, string outputPath, string commandLineArguments,
        Guid userId, TranscodingJobType transcodingJobType, CancellationTokenSource cancellationTokenSource,
        string? workingDirectory = null)
    {
        var command = commandLineArguments;
        try
        {
            if (!cancellationTokenSource.IsCancellationRequested)
                command = Plan(state, command, userId, transcodingJobType, OperatingSystem.IsLinux());
        }
        catch { } // A planner failure must keep Jellyfin's original startup behavior.
        if (!string.Equals(command, commandLineArguments, StringComparison.Ordinal))
        {
            try
            {
                command = await _probe.ApplyAsync(state, command, mediaEncoder?.ProbePath, cancellationTokenSource.Token,
                    result => logger?.LogInformation("Kaevo transport probe outcome={Outcome}", result)).ConfigureAwait(false);
            }
            catch (Exception) { } // Preserve the original full probe on any validation failure.
        }
        return await inner.StartFfMpeg(state, outputPath, command, userId, transcodingJobType,
            cancellationTokenSource, workingDirectory).ConfigureAwait(false);
    }
    public TranscodingJob? GetTranscodingJob(string session) => inner.GetTranscodingJob(session);
    public TranscodingJob? GetTranscodingJob(string path, TranscodingJobType type) => inner.GetTranscodingJob(path, type);
    public void PingTranscodingJob(string session, bool? paused) => inner.PingTranscodingJob(session, paused);
    public Task KillTranscodingJobs(string device, string? session, Func<string, bool> deleteFiles)
        => inner.KillTranscodingJobs(device, session, deleteFiles);
    public void ReportTranscodingProgress(TranscodingJob job, StreamState state, TimeSpan? position, float? framerate,
        double? percent, long? bytes, int? bitrate) => inner.ReportTranscodingProgress(job, state, position, framerate, percent, bytes, bitrate);
    public TranscodingJob? OnTranscodeBeginRequest(string path, TranscodingJobType type) => inner.OnTranscodeBeginRequest(path, type);
    public void OnTranscodeEndRequest(TranscodingJob job) => inner.OnTranscodeEndRequest(job);
    public ValueTask<IDisposable> LockAsync(string path, CancellationToken cancellationToken) => inner.LockAsync(path, cancellationToken);

    internal static void Register(IServiceCollection services)
    {
        var matches = services.Where(d => d.ServiceType == typeof(ITranscodeManager)).ToArray();
        // Unknown overrides and registrations keep their existing behavior.
        if (matches.Length != 1 || matches[0].Lifetime != ServiceLifetime.Singleton
            || matches[0].ImplementationType?.FullName != "MediaBrowser.MediaEncoding.Transcoding.TranscodeManager"
            || services.Any(d => d.ServiceType == matches[0].ImplementationType)) return;
        var original = matches[0];
        services.Remove(original);
        // Register the original separately so DI still owns its disposal.
        services.AddSingleton(original.ImplementationType!);
        services.AddSingleton<ITranscodeManager>(p => new KaevoHardwareTranscodeManager(
            (ITranscodeManager)p.GetRequiredService(original.ImplementationType!),
            p.GetRequiredService<IMediaEncoder>(), p.GetRequiredService<ILogger<KaevoHardwareTranscodeManager>>()));
    }

    private sealed class Lease(Action release) : IDisposable
    {
        private Action? _release = release;
        public void Dispose() => Interlocked.Exchange(ref _release, null)?.Invoke();
    }
}
