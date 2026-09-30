using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using MediaBrowser.Common.Configuration;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.MediaEncoding;
using Microsoft.Extensions.Logging;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

/// Produces an item-scoped HLS rendition whose audio timestamps are corrected
/// without modifying the library file. Video is encoded to the iOS baseline
/// instead of copied blindly, so an offset never turns an otherwise
/// incompatible source into audio-only playback.
public sealed class KaevoAudioSyncTranscoder
{
    public const int MaximumOffsetMilliseconds = 5_000;
    private static readonly TimeSpan StartupTimeout = TimeSpan.FromSeconds(12);
    private static readonly TimeSpan SessionLifetime = TimeSpan.FromHours(2);
    private readonly ConcurrentDictionary<string, Session> _sessions = new(StringComparer.Ordinal);
    private readonly object _sessionGate = new();
    private readonly ILibraryManager _libraryManager;
    private readonly IMediaEncoder _mediaEncoder;
    private readonly ILogger<KaevoAudioSyncTranscoder> _logger;
    private readonly string _root;

    public KaevoAudioSyncTranscoder(
        ILibraryManager libraryManager,
        IMediaEncoder mediaEncoder,
        IApplicationPaths applicationPaths,
        ILogger<KaevoAudioSyncTranscoder> logger)
    {
        _libraryManager = libraryManager;
        _mediaEncoder = mediaEncoder;
        _logger = logger;
        _root = Path.Combine(applicationPaths.DataPath, "kaevo", "audio-sync");
        Directory.CreateDirectory(_root);
    }

    public async Task<string> PrepareAsync(
        string itemId,
        string playSessionId,
        int audioOffsetMilliseconds,
        int? audioStreamIndex,
        long startTimeTicks,
        CancellationToken cancellationToken)
    {
        var request = Validate(itemId, playSessionId, audioOffsetMilliseconds, audioStreamIndex, startTimeTicks);
        CleanupExpired();
        var key = $"{request.ItemId}:{request.PlaySessionId}:{request.OffsetMilliseconds}:{request.AudioStreamIndex}:{request.StartTimeTicks}";
        Session session;
        lock (_sessionGate)
        {
            // Concurrent playlist requests must not launch orphan encoders.
            session = _sessions.GetOrAdd(key, _ => Start(request));
        }
        var deadline = DateTime.UtcNow + StartupTimeout;
        while (DateTime.UtcNow < deadline)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                Stop(request.PlaySessionId);
                cancellationToken.ThrowIfCancellationRequested();
            }
            if (Ready(session.PlaylistPath)) return session.PlaylistPath;
            if (session.Process.HasExited)
            {
                Stop(request.PlaySessionId);
                throw new InvalidOperationException("audioSyncTranscodeFailed");
            }
            try { await Task.Delay(100, cancellationToken).ConfigureAwait(false); }
            catch (OperationCanceledException) { Stop(request.PlaySessionId); throw; }
        }
        Stop(request.PlaySessionId);
        throw new InvalidOperationException("audioSyncStartupTimedOut");
    }

    public string SegmentPath(string playSessionId, string fileName)
    {
        if (!SafeIdentifier(playSessionId) || !SafeSegment(fileName))
        {
            throw new InvalidOperationException("audioSyncResourceInvalid");
        }
        var session = _sessions.Values.FirstOrDefault(value =>
            string.Equals(value.PlaySessionId, playSessionId, StringComparison.Ordinal));
        if (session is null) throw new FileNotFoundException();
        var path = Path.Combine(session.Directory, fileName);
        if (!File.Exists(path)) throw new FileNotFoundException();
        return path;
    }

    internal static string AudioFilter(int offsetMilliseconds)
    {
        var seconds = (Math.Abs(offsetMilliseconds) / 1_000d).ToString("0.###", CultureInfo.InvariantCulture);
        return offsetMilliseconds > 0
            ? $"asetpts=PTS-STARTPTS,adelay={offsetMilliseconds}:all=1"
            : $"atrim=start={seconds},asetpts=PTS-STARTPTS";
    }

    private Session Start(Request request)
    {
        var item = _libraryManager.GetItemById(Guid.Parse(request.ItemId))
            ?? throw new InvalidOperationException("audioSyncItemMissing");
        if (string.IsNullOrWhiteSpace(item.Path) || !Path.IsPathFullyQualified(item.Path) || !File.Exists(item.Path))
        {
            throw new InvalidOperationException("audioSyncSourceUnavailable");
        }
        if (string.IsNullOrWhiteSpace(_mediaEncoder.EncoderPath) || !File.Exists(_mediaEncoder.EncoderPath))
        {
            throw new InvalidOperationException("audioSyncEncoderUnavailable");
        }

        var directory = Path.Combine(_root, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var playlist = Path.Combine(directory, "main.m3u8");
        var process = new Process {
            StartInfo = new ProcessStartInfo {
                FileName = _mediaEncoder.EncoderPath,
                UseShellExecute = false,
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                CreateNoWindow = true
            }
        };
        var arguments = process.StartInfo.ArgumentList;
        arguments.Add("-hide_banner"); arguments.Add("-loglevel"); arguments.Add("warning");
        if (request.StartTimeTicks > 0) {
            arguments.Add("-ss");
            arguments.Add((request.StartTimeTicks / 10_000_000d).ToString("0.###", CultureInfo.InvariantCulture));
        }
        // Each HLS rendition has an elapsed clock. The app maps it back to
        // StartTimeTicks; resetting PTS also keeps the keyframe interval from
        // forcing every frame after a deep input seek.
        arguments.Add("-i"); arguments.Add(item.Path);
        arguments.Add("-map"); arguments.Add("0:v:0");
        arguments.Add("-map"); arguments.Add(request.AudioStreamIndex is int index ? $"0:{index}" : "0:a:0");
        arguments.Add("-map_metadata"); arguments.Add("-1");
        arguments.Add("-map_chapters"); arguments.Add("-1");
        arguments.Add("-vf"); arguments.Add("setpts=PTS-STARTPTS,scale=w='min(1280,iw)':h='min(720,ih)':force_original_aspect_ratio=decrease:force_divisible_by=2");
        arguments.Add("-c:v"); arguments.Add("libx264");
        arguments.Add("-preset"); arguments.Add("veryfast");
        arguments.Add("-crf"); arguments.Add("20");
        arguments.Add("-pix_fmt"); arguments.Add("yuv420p");
        arguments.Add("-force_key_frames"); arguments.Add("expr:gte(t,n_forced*2)");
        arguments.Add("-c:a"); arguments.Add("aac");
        arguments.Add("-b:a"); arguments.Add("192k");
        arguments.Add("-af"); arguments.Add(AudioFilter(request.OffsetMilliseconds));
        arguments.Add("-f"); arguments.Add("hls");
        arguments.Add("-hls_time"); arguments.Add("2");
        arguments.Add("-hls_playlist_type"); arguments.Add("event");
        arguments.Add("-hls_segment_type"); arguments.Add("fmp4");
        arguments.Add("-hls_fmp4_init_filename"); arguments.Add("init.mp4");
        arguments.Add("-hls_segment_filename"); arguments.Add(Path.Combine(directory, "segment%06d.m4s"));
        arguments.Add("-hls_flags"); arguments.Add("independent_segments+temp_file");
        arguments.Add("-y"); arguments.Add(playlist);
        process.Start();
        _ = DrainAsync(process.StandardOutput);
        var observation = ObserveErrorsAsync(process);
        return new Session(request.PlaySessionId, directory, playlist, process, DateTime.UtcNow, observation);
    }

    private async Task ObserveErrorsAsync(Process process)
    {
        var stderr = await process.StandardError.ReadToEndAsync().ConfigureAwait(false);
        await process.WaitForExitAsync().ConfigureAwait(false);
        if (process.ExitCode != 0)
        {
            _logger.LogWarning("Kaevo audio sync transcode exited with code {ExitCode}: {Category}", process.ExitCode,
                string.IsNullOrWhiteSpace(stderr) ? "noDiagnostic" : "ffmpegDiagnosticAvailable");
        }
    }

    private static async Task DrainAsync(StreamReader reader)
    {
        while (await reader.ReadLineAsync().ConfigureAwait(false) is not null) { }
    }

    private static bool Ready(string path)
    {
        try {
            return File.Exists(path) && File.ReadAllText(path).Contains("#EXTINF", StringComparison.Ordinal);
        } catch (IOException) { return false; }
    }

    public void Stop(string playSessionId)
    {
        if (!SafeIdentifier(playSessionId)) return;
        lock (_sessionGate)
        {
            foreach (var pair in _sessions.Where(pair => pair.Value.PlaySessionId == playSessionId))
            {
                if (!_sessions.TryRemove(pair.Key, out var session)) continue;
                _ = ReleaseAsync(session);
            }
        }
    }

    private void CleanupExpired()
    {
        var cutoff = DateTime.UtcNow - SessionLifetime;
        lock (_sessionGate)
        {
            // A completed encoder still owns playable files. Keep them until
            // playback stops or the session expires, not merely process exit.
            foreach (var pair in _sessions.Where(pair => pair.Value.CreatedAt < cutoff))
            {
                if (_sessions.TryRemove(pair.Key, out var session)) _ = ReleaseAsync(session);
            }
        }
    }

    private static async Task ReleaseAsync(Session session)
    {
        try
        {
            if (!session.Process.HasExited) session.Process.Kill(entireProcessTree: true);
            await session.Observation.ConfigureAwait(false);
        }
        catch (InvalidOperationException) { }
        finally
        {
            try { Directory.Delete(session.Directory, recursive: true); } catch { }
            session.Process.Dispose();
        }
    }

    private static Request Validate(string itemId, string playSessionId, int offset, int? audioStreamIndex, long startTimeTicks)
    {
        if (!Guid.TryParseExact(itemId, "N", out var id) && !Guid.TryParse(itemId, out id))
            throw new InvalidOperationException("audioSyncItemInvalid");
        if (!SafeIdentifier(playSessionId) || offset == 0 || Math.Abs(offset) > MaximumOffsetMilliseconds
            || audioStreamIndex is < 0 or > 10_000 || startTimeTicks < 0)
            throw new InvalidOperationException("audioSyncRequestInvalid");
        return new Request(id.ToString("N"), playSessionId, offset, audioStreamIndex, startTimeTicks);
    }

    private static bool SafeIdentifier(string value) => value.Length is > 0 and <= 128
        && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.' or ':');
    private static bool SafeSegment(string value) => value == "init.mp4"
        || (value.StartsWith("segment", StringComparison.Ordinal) && value.EndsWith(".m4s", StringComparison.Ordinal)
            && value[7..^4].Length is > 0 and <= 6 && value[7..^4].All(char.IsAsciiDigit));

    private sealed record Request(string ItemId, string PlaySessionId, int OffsetMilliseconds, int? AudioStreamIndex, long StartTimeTicks);
    private sealed record Session(string PlaySessionId, string Directory, string PlaylistPath, Process Process, DateTime CreatedAt, Task Observation);
}
