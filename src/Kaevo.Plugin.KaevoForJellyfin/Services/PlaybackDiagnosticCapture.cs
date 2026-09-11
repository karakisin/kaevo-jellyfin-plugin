using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

// Timings only. The administrator opts into one command and at most sixteen
// requests for its exact playback session. No authorization or media behavior.
internal sealed class PlaybackDiagnosticCapture(TimeProvider? clock = null)
{
    internal const int MaximumMediaRequests = 16;
    private readonly TimeProvider _clock = clock ?? TimeProvider.System;
    private readonly object _sync = new();
    private long _window, _armed;
    private bool _commandUsed;
    private PlaybackDiagnosticTrace? _commandTrace;
    private int _mediaUsed;
    private string? _session, _claimedRequest;
    private long _claimStarted, _claimCompleted;
    public long Timestamp => _clock.GetTimestamp();

    internal static string Tag(string value) => Convert.ToHexString(
        SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant()[..20];

    private bool Open(long expires)
    {
        var now = _clock.GetUtcNow().ToUnixTimeSeconds();
        if (expires <= now || expires > now + 300) return false;
        if (_window != expires)
        {
            _window = expires; _armed = Timestamp; _commandUsed = false;
            _mediaUsed = 0; _session = null; _claimedRequest = null; _commandTrace = null;
        }
        return _clock.GetElapsedTime(_armed, Timestamp) < TimeSpan.FromMinutes(5);
    }

    public void RememberClaim(long expires, string requestId, long started)
    {
        lock (_sync)
        {
            if (!Open(expires) || _commandUsed || _claimedRequest is not null) return;
            _claimedRequest = Tag(requestId); _claimStarted = started; _claimCompleted = Timestamp;
        }
    }

    public PlaybackDiagnosticTrace? BeginCommand(long expires, string requestId, Action<string> sink)
    {
        lock (_sync)
        {
            if (!Open(expires) || _commandUsed) return null;
            _commandUsed = true;
            var tag = Tag(requestId);
            var trace = new PlaybackDiagnosticTrace(_clock, "command", tag, sink,
                _claimedRequest == tag ? _claimStarted : Timestamp);
            if (_claimedRequest == tag) trace.MarkAt(PlaybackDiagnosticStep.ClaimReceived, _claimCompleted);
            trace.Mark(PlaybackDiagnosticStep.CommandReceived);
            _commandTrace = trace;
            return trace;
        }
    }

    public void BindSession(long expires, PlaybackDiagnosticTrace trace, string session)
    {
        lock (_sync) { if (Open(expires) && ReferenceEquals(_commandTrace, trace) && _session is null) _session = Tag(session); }
    }

    public PlaybackDiagnosticTrace? BeginMedia(long expires, string session, string requestId, Action<string> sink, long received)
    {
        lock (_sync)
        {
            if (!Open(expires) || _session != Tag(session) || _mediaUsed >= MaximumMediaRequests) return null;
            _mediaUsed++;
            return new PlaybackDiagnosticTrace(_clock, "media", Tag(requestId), sink, received);
        }
    }
}

internal enum PlaybackDiagnosticStep
{
    ClaimReceived, CommandReceived, SecretsReady, ExecuteComplete, CompletionSent,
    UpstreamRequest, UpstreamHeaders, UpstreamBody, UpstreamParsed,
    Authorized, HeadersSent, FirstBodyRead, FirstBodySent, PlaylistRewritten, Finished
}
internal enum PlaybackDiagnosticResource { None, Authority, PlaybackInfo, Trickplay, MediaSegments, Other }
internal enum PlaybackDiagnosticOutcome { Complete, Cancelled, Http, Invalid, Socket, Other }

internal sealed class PlaybackDiagnosticTrace(TimeProvider clock, string kind, string requestTag, Action<string> sink, long started) : IDisposable
{
    private readonly object _sync = new();
    private readonly List<object> _points = [];
    private readonly HashSet<(PlaybackDiagnosticStep, PlaybackDiagnosticResource)> _seen = [];
    private bool _disposed;
    public PlaybackDiagnosticOutcome Outcome { get; set; }
    public void Mark(PlaybackDiagnosticStep step, PlaybackDiagnosticResource resource = PlaybackDiagnosticResource.None, int status = 0)
        => MarkAt(step, clock.GetTimestamp(), resource, status);
    public void MarkAt(PlaybackDiagnosticStep step, long timestamp, PlaybackDiagnosticResource resource = PlaybackDiagnosticResource.None, int status = 0)
    {
        lock (_sync)
        {
            if (_disposed || _points.Count >= 32 || !_seen.Add((step, resource))) return;
            _points.Add(new { step = step.ToString(), resource = resource.ToString(),
                elapsed_ms = Math.Round(Math.Max(0, clock.GetElapsedTime(started, timestamp).TotalMilliseconds), 2),
                status = status is >= 100 and <= 599 ? status : 0 });
        }
    }
    public void Fail(Exception exception) => Outcome = exception switch
    {
        OperationCanceledException => PlaybackDiagnosticOutcome.Cancelled,
        HttpRequestException => PlaybackDiagnosticOutcome.Http,
        System.Net.WebSockets.WebSocketException => PlaybackDiagnosticOutcome.Socket,
        InvalidOperationException or JsonException => PlaybackDiagnosticOutcome.Invalid,
        _ => PlaybackDiagnosticOutcome.Other
    };
    public void Dispose()
    {
        lock (_sync)
        {
            if (_disposed) return;
            Mark(PlaybackDiagnosticStep.Finished); _disposed = true;
            // Diagnostics must never turn a successful playback/stop into failure.
            try { sink(JsonSerializer.Serialize(new { version = 1, kind, request_tag = requestTag, outcome = Outcome.ToString(), points = _points })); }
            catch { }
        }
    }
    internal static PlaybackDiagnosticResource Resource(string path)
    {
        if (path.StartsWith("/Items/", StringComparison.Ordinal) && path.Contains("/PlaybackInfo?", StringComparison.Ordinal)) return PlaybackDiagnosticResource.PlaybackInfo;
        if (path.StartsWith("/MediaSegments/", StringComparison.Ordinal)) return PlaybackDiagnosticResource.MediaSegments;
        if (path.StartsWith("/Users/", StringComparison.Ordinal) && path.Contains("/Items/", StringComparison.Ordinal))
            return path.Contains("Fields=Trickplay", StringComparison.Ordinal) ? PlaybackDiagnosticResource.Trickplay : PlaybackDiagnosticResource.Authority;
        return PlaybackDiagnosticResource.Other;
    }
}
