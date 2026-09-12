using System.Globalization;
using System.Text.Json;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

/// <summary>Only local, explicit-Play encoder scheduling. This object never issues a grant or serves media.</summary>
internal sealed class KaevoOriginStart
{
    private readonly object _gate = new();
    private readonly Dictionary<string, Entry> _pending = new(StringComparer.Ordinal);
    private const int MaximumPending = 2;

    private sealed class Entry(PlaybackOriginScope scope)
    {
        internal readonly PlaybackOriginScope Scope = scope;
        internal readonly TaskCompletionSource<bool> Handoff = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal bool Promoted;
        internal bool Closing;
        internal string? Segment;
    }

    internal bool TryStart(PlaybackOriginScope scope, long deadline, Func<string, CancellationToken, Task<string>> playlist,
        Func<string, CancellationToken, Task> segment, Func<Task> stop, Action<string> diagnostic,
        CancellationToken lifetime, DateTimeOffset? now = null)
    {
        var instant = now ?? DateTimeOffset.UtcNow;
        if (deadline <= instant.ToUnixTimeSeconds() || deadline > instant.ToUnixTimeSeconds() + 30
            || lifetime.IsCancellationRequested)
            return false;
        var remaining = DateTimeOffset.FromUnixTimeSeconds(deadline) - instant;
        Entry entry;
        lock (_gate)
        {
            if (_pending.Count >= MaximumPending || _pending.ContainsKey(scope.PlaySessionId)) return false;
            entry = new Entry(scope);
            _pending.Add(scope.PlaySessionId, entry);
        }
        // Tracked, bounded by both the authenticated claim deadline and the
        // connector lifetime. Completion/cleanup is owned by RunAsync.
        _ = RunAsync(entry, remaining, playlist, segment, stop, diagnostic, lifetime);
        return true;
    }

    private async Task RunAsync(Entry entry, TimeSpan remaining, Func<string, CancellationToken, Task<string>> playlist,
        Func<string, CancellationToken, Task> segment, Func<Task> stop, Action<string> diagnostic, CancellationToken lifetime)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(lifetime);
        timeout.CancelAfter(remaining);
        try
        {
            diagnostic("started");
            var masterPath = entry.Scope.MasterPath;
            var master = await playlist(masterPath, timeout.Token).ConfigureAwait(false);
            var mediaPath = entry.Scope.FirstVariant(master, masterPath);
            var media = await playlist(mediaPath, timeout.Token).ConfigureAwait(false);
            var segmentPath = entry.Scope.ResumeSegment(media, mediaPath);
            lock (_gate) entry.Segment = segmentPath.Split('?', 2)[0];
            // Only a two-byte local read. Normal Jellyfin HLS files are reused
            // by AVPlayer; no complete movie or cloud prefetch is created.
            await segment(segmentPath, timeout.Token).ConfigureAwait(false);
            diagnostic("segment_ready");
            await entry.Handoff.Task.WaitAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { diagnostic("cancelled"); }
        catch (Exception) { diagnostic("unavailable"); }
        finally
        {
            bool promoted;
            lock (_gate)
            {
                entry.Closing = true;
                promoted = entry.Promoted;
            }
            try
            {
                if (!promoted)
                {
                    await stop().ConfigureAwait(false);
                    diagnostic("abandoned_job_stopped");
                }
            }
            catch (Exception) { diagnostic("stop_failed"); }
            finally
            {
                lock (_gate) _pending.Remove(entry.Scope.PlaySessionId);
            }
        }
    }

    /// Called only after a real signed media request sends its first body to the relay.
    internal void Delivered(PlaybackGrant grant, string path)
    {
        lock (_gate)
        {
            if (!_pending.TryGetValue(grant.PlaybackSessionId, out var entry) || entry.Closing
                || entry.Scope.ConnectorId != grant.ConnectorId || entry.Scope.DeviceId != grant.DeviceId
                || entry.Scope.ItemId != grant.ItemId || entry.Scope.MediaSourceId != grant.MediaSourceId
                || entry.Segment != path.Split('?', 2)[0]) return;
            entry.Promoted = true;
            entry.Handoff.TrySetResult(true);
        }
    }
}

internal sealed record PlaybackOriginScope(string ConnectorId, string DeviceId, string ItemId,
    string MediaSourceId, string PlaySessionId, int MaximumBitrate, int? AudioIndex, long PositionTicks)
{
    internal string MasterPath => $"/Videos/{Uri.EscapeDataString(ItemId)}/master.m3u8?" + string.Join('&',
        Rendition().Select(pair => $"{Uri.EscapeDataString(pair.Key)}={Uri.EscapeDataString(pair.Value)}"));

    // Same conservative native transcode recipe. The encoder implementation
    // remains Jellyfin's configured QSV/VAAPI/NVENC/other supported backend.
    internal Dictionary<string, string> Rendition()
    {
        var query = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["videoCodec"] = "h264", ["audioCodec"] = "aac",
            ["videoBitRate"] = Math.Min(Math.Max(MaximumBitrate - 192_000, 1), 11_808_000).ToString(CultureInfo.InvariantCulture),
            ["audioBitRate"] = "192000", ["maxWidth"] = "1920", ["maxHeight"] = "1080",
            ["enableAdaptiveBitrateStreaming"] = "true", ["allowVideoStreamCopy"] = "false",
            ["allowAudioStreamCopy"] = "false", ["enableAutoStreamCopy"] = "false",
            ["segmentContainer"] = "ts", ["segmentLength"] = "4", ["minSegments"] = "1",
            ["enableSubtitlesInManifest"] = "true", ["mediaSourceId"] = MediaSourceId,
            ["playSessionId"] = PlaySessionId, ["deviceId"] = DeviceId
        };
        if (AudioIndex is not null) query["audioStreamIndex"] = AudioIndex.Value.ToString(CultureInfo.InvariantCulture);
        return query;
    }

    internal string FirstVariant(string text, string source)
    {
        var variant = false;
        foreach (var line in Lines(text))
        {
            if (line.StartsWith("#EXT-X-STREAM-INF:", StringComparison.Ordinal)) variant = true;
            else if (variant && !line.StartsWith('#')) return Child(line, source, ".m3u8");
        }
        throw new InvalidOperationException("originPlaylistInvalid");
    }

    internal string ResumeSegment(string text, string source)
    {
        double start = 0;
        double? duration = null;
        var position = PositionTicks / 10_000_000.0;
        var lines = Lines(text);
        // v1 handles simple full-timeline TS VOD only. Encrypted, mapped,
        // discontinuous or ranged media remains the normal native path.
        if (!lines.Contains("#EXT-X-ENDLIST") || lines.Any(line => line.StartsWith("#EXT-X-KEY:")
            || line.StartsWith("#EXT-X-MAP:") || line.StartsWith("#EXT-X-BYTERANGE:")
            || line.StartsWith("#EXT-X-DISCONTINUITY"))) throw new InvalidOperationException("originPlaylistUnsupported");
        foreach (var line in lines)
        {
            if (line.StartsWith("#EXTINF:", StringComparison.Ordinal))
            {
                if (!double.TryParse(line[8..].Split(',', 2)[0], NumberStyles.Float, CultureInfo.InvariantCulture,
                    out var parsed) || !double.IsFinite(parsed) || parsed <= 0 || parsed > 10)
                    throw new InvalidOperationException("originPlaylistInvalid");
                duration = parsed;
            }
            else if (!line.StartsWith('#'))
            {
                if (duration is null) throw new InvalidOperationException("originPlaylistInvalid");
                var child = Child(line, source, ".ts");
                if (start <= position && position < start + duration.Value) return child;
                start += duration.Value;
                duration = null;
            }
        }
        throw new InvalidOperationException("originResumeUnavailable");
    }

    private static string[] Lines(string text)
    {
        if (!text.StartsWith("#EXTM3U", StringComparison.Ordinal) || text.Length > 2 * 1_048_576)
            throw new InvalidOperationException("originPlaylistInvalid");
        return text.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    private string Child(string value, string source, string extension)
    {
        var root = new Uri("https://origin.invalid");
        if (value.StartsWith("//", StringComparison.Ordinal) || value.Contains('#')
            || (!value.StartsWith('/') && Uri.TryCreate(value, UriKind.Absolute, out _))
            || !Uri.TryCreate(new Uri(root, source), value, out var resolved)
            || resolved.Scheme != "https" || resolved.Host != root.Host
            || !resolved.AbsolutePath.EndsWith(extension, StringComparison.Ordinal)
            || !KaevoPlaybackSecurity.IsHlsSessionResourcePath(Uri.UnescapeDataString(resolved.AbsolutePath), ItemId, MediaSourceId))
            throw new InvalidOperationException("originScopeInvalid");
        var query = new Dictionary<string, JsonElement>(StringComparer.OrdinalIgnoreCase);
        foreach (var pair in resolved.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = pair.Split('=', 2);
            var key = Uri.UnescapeDataString(parts[0]);
            if (key.Equals("api_key", StringComparison.OrdinalIgnoreCase)) continue;
            if (!query.TryAdd(key, JsonSerializer.SerializeToElement(parts.Length == 2 ? Uri.UnescapeDataString(parts[1]) : "")))
                throw new InvalidOperationException("originScopeInvalid");
        }
        // Reuse the same exact item/source/session/query bounds as real media
        // delivery. This is validation only, not a signed grant or receipt.
        var scope = new PlaybackGrant(ConnectorId, DeviceId, ItemId, MediaSourceId, PlaySessionId,
            "transcode", MaximumBitrate, 0);
        return KaevoPlaybackSecurity.Resolve(scope, "GET", resolved.AbsolutePath, query, null).PathAndQuery;
    }
}
