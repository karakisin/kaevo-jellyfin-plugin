using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using MediaBrowser.Controller.Streaming;
using MediaBrowser.Model.Entities;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

// Called only after the exact, one-use Kaevo hardware admission is consumed.
// A small probe must independently recover the selected streams before its
// limits can be used by the encoder. Unknown files retain Jellyfin's full probe.
internal sealed class KaevoValidatedTransportProbe
{
    internal const string OriginalPrefix = "-analyzeduration 200M -probesize 1G ";
    internal const string ValidatedPrefix = "-analyzeduration 10M -probesize 10M ";
    private readonly SemaphoreSlim _slots = new(2, 2);
    private readonly object _gate = new();
    private readonly HashSet<string> _validated = new(StringComparer.Ordinal);
    private readonly string? _cachePath;

    internal KaevoValidatedTransportProbe(string? cachePath = null)
    {
        _cachePath = cachePath;
        try
        {
            if (cachePath is null || !File.Exists(cachePath) || new FileInfo(cachePath).Length > 8192) return;
            var entries = JsonSerializer.Deserialize<string[]>(File.ReadAllText(cachePath));
            if (entries is null || entries.Length > 64 || entries.Any(e => e is null || e.Length != 64
                || e.Any(c => !char.IsAsciiHexDigit(c)))) return;
            foreach (var entry in entries) _validated.Add(entry);
        }
        catch { } // A lost or damaged cache only requires fresh independent validation.
    }

    private void RetainValidation(string fingerprint)
    {
        lock (_gate)
        {
            if (_validated.Count >= 64) _validated.Clear();
            _validated.Add(fingerprint);
            try
            {
                if (_cachePath is null) return;
                Directory.CreateDirectory(Path.GetDirectoryName(_cachePath)!);
                var temporary = _cachePath + ".tmp";
                File.WriteAllText(temporary, JsonSerializer.Serialize(_validated));
                File.Move(temporary, _cachePath, overwrite: true);
            }
            catch { } // Cache persistence cannot prevent playback.
        }
    }

    internal async Task<string> ApplyAsync(StreamState state, string command, string? probePath,
        CancellationToken cancellationToken, Action<string> diagnostic)
    {
        if (!Eligible(state, command) || string.IsNullOrWhiteSpace(probePath) || !File.Exists(probePath)) return command;
        var path = state.MediaSource.Path;
        var video = state.VideoStream;
        var audio = state.AudioStream;
        try
        {
            var fingerprint = Fingerprint(path, video, audio);
            lock (_gate)
                if (_validated.Contains(fingerprint))
                {
                    diagnostic("cached");
                    return ValidatedPrefix + command[OriginalPrefix.Length..];
                }
            if (!await _slots.WaitAsync(0, cancellationToken).ConfigureAwait(false)) return command;
            try
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(TimeSpan.FromSeconds(2));
                var info = new ProcessStartInfo(probePath)
                {
                    UseShellExecute = false, CreateNoWindow = true,
                    RedirectStandardOutput = true, RedirectStandardError = true
                };
                foreach (var argument in new[] { "-v", "error", "-analyzeduration", "10M", "-probesize", "10M",
                    "-show_entries", "stream=index,codec_name,codec_type,width,height,sample_rate,channels,pix_fmt,profile", "-of", "json", path })
                    info.ArgumentList.Add(argument);
                using var process = new Process { StartInfo = info };
                try
                {
                    if (!process.Start()) return command;
                    var output = ReadBoundedAsync(process.StandardOutput, 32_768, timeout.Token);
                    var error = ReadBoundedAsync(process.StandardError, 8_192, timeout.Token);
                    await Task.WhenAll(output, error, process.WaitForExitAsync(timeout.Token)).ConfigureAwait(false);
                    if (process.ExitCode != 0 || !string.IsNullOrWhiteSpace(await error.ConfigureAwait(false))) return command;
                    using var parsed = JsonDocument.Parse(await output.ConfigureAwait(false));
                    if (!Matches(parsed.RootElement, video, audio) || Fingerprint(path, video, audio) != fingerprint) return command;
                    RetainValidation(fingerprint);
                    diagnostic("validated");
                    return ValidatedPrefix + command[OriginalPrefix.Length..];
                }
                finally
                {
                    try { if (!process.HasExited) process.Kill(entireProcessTree: true); }
                    catch (InvalidOperationException) { }
                }
            }
            finally { _slots.Release(); }
        }
        catch (Exception) { diagnostic("full_probe_fallback"); return command; }
    }

    internal static bool Eligible(StreamState state, string command)
    {
        var source = state.MediaSource;
        var video = state.VideoStream;
        var audio = state.AudioStream;
        var path = source?.Path;
        return source is not null && !source.IsRemote && source.Container is "ts" or "m2ts" or "mkv" or "matroska"
            && !string.IsNullOrWhiteSpace(path) && Path.IsPathFullyQualified(path)
            && !path.Any(c => char.IsControl(c) || c == '"')
            && video is { Codec: "hevc", Width: > 0, Height: > 0, BitDepth: 10 }
            && audio is { SampleRate: > 0, Channels: > 0 } && !string.IsNullOrWhiteSpace(audio.Codec)
            && video.Index >= 0 && audio.Index >= 0 && video.Index != audio.Index
            && command.StartsWith(OriginalPrefix, StringComparison.Ordinal)
            && command.Contains(source.Container is "mkv" or "matroska" ? "-f matroska " : "-f mpegts ", StringComparison.Ordinal)
            && command.Contains($"-map 0:{video.Index} ", StringComparison.Ordinal)
            && command.Contains($"-map 0:{audio.Index} ", StringComparison.Ordinal)
            && command.Contains("-map -0:s ", StringComparison.Ordinal)
            && (command.Contains($"-i file:\"{path}\" ", StringComparison.Ordinal)
                || command.Contains($"-i \"file:{path}\" ", StringComparison.Ordinal));
    }

    internal static bool Matches(JsonElement root, MediaStream video, MediaStream audio)
    {
        if (!root.TryGetProperty("streams", out var streams) || streams.ValueKind != JsonValueKind.Array) return false;
        var all = streams.EnumerateArray().ToArray();
        if (all.Any(s => s.ValueKind != JsonValueKind.Object)) return false;
        bool Selected(MediaStream expected, bool isVideo)
        {
            var candidates = all.Where(s => Integer(s, "index") == expected.Index).ToArray();
            if (candidates.Length != 1) return false;
            var stream = candidates[0];
            if (Text(stream, "codec_name") != expected.Codec || Text(stream, "codec_type") != (isVideo ? "video" : "audio")) return false;
            return isVideo
                ? Integer(stream, "width") == expected.Width && Integer(stream, "height") == expected.Height
                    && Text(stream, "pix_fmt") == "yuv420p10le" && Text(stream, "profile") == expected.Profile
                : Integer(stream, "sample_rate") == expected.SampleRate && Integer(stream, "channels") == expected.Channels;
        }
        return Selected(video, true) && Selected(audio, false);
    }

    private static string? Text(JsonElement item, string key) => item.TryGetProperty(key, out var value)
        && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
    private static int? Integer(JsonElement item, string key)
    {
        if (!item.TryGetProperty(key, out var value)) return null;
        if (value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out var number)) return number;
        return value.ValueKind == JsonValueKind.String && int.TryParse(value.GetString(), NumberStyles.None,
            CultureInfo.InvariantCulture, out var textNumber) ? textNumber : null;
    }
    private static string Fingerprint(string path, MediaStream video, MediaStream audio)
    {
        var file = new FileInfo(path);
        var identity = string.Join('|', "bounded-probe-v1", path, file.Length, file.LastWriteTimeUtc.Ticks, video.Index, video.Codec,
            video.Width, video.Height, video.Profile, audio.Index, audio.Codec, audio.SampleRate, audio.Channels);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(identity)));
    }
    private static async Task<string> ReadBoundedAsync(StreamReader reader, int maximum, CancellationToken token)
    {
        var result = new StringBuilder(); var buffer = new char[2048];
        while (true)
        {
            var count = await reader.ReadAsync(buffer.AsMemory(), token).ConfigureAwait(false);
            if (count == 0) return result.ToString();
            if (result.Length + count > maximum) throw new IOException("probeOutputTooLarge");
            result.Append(buffer, 0, count);
        }
    }
}
