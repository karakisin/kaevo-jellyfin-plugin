using System.Text;
using MediaBrowser.Controller.MediaEncoding;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

[Flags]
internal enum OriginLogPhase
{
    None = 0, Attached = 1, DriverOpened = 2, InputOpened = 4,
    StreamsMapped = 8, OutputOpened = 16, Progress = 32, Unavailable = 64
}

// Observes Jellyfin's existing, line-flushed log; never consumes StandardError.
// No log text, command, source path, or credentials leave this object.
internal sealed class OriginEncoderLogObservation(string? directory)
{
    internal const int MaximumBytes = 512 * 1024;
    internal const int HeaderBytes = 128 * 1024;
    internal const int ReadBytes = 16 * 1024;
    internal const int MaximumCandidates = 64;
    internal const int MaximumSearches = 8;
    private int _bytes, _searches, _samples;
    private string? _path, _command;
    private long _offset;
    private readonly StringBuilder _line = new();
    private OriginLogPhase _phases;
    private TranscodingJob? _job;
    private int? _pid;
    private DateTime? _processStarted, _created;

    internal OriginLogPhase Read(TranscodingJob job)
    {
        if ((_phases & OriginLogPhase.Unavailable) != 0 || (_phases & OriginLogPhase.Progress) != 0) return _phases;
        try
        {
            if (directory is null || !Path.IsPathFullyQualified(directory) || job.Process is null) return _phases;
            var pid = job.Process.Id;
            var started = job.Process.StartTime.ToUniversalTime();
            if (_job is not null && (!ReferenceEquals(_job, job) || _pid != pid || _processStarted != started)) return Unavailable();
            _job = job; _pid = pid; _processStarted = started;
            // The caller has already verified the exact source/device/session.
            // A replaced process/command must never inherit the prior log.
            var command = job.Process.StartInfo.FileName + " " + job.Process.StartInfo.Arguments;
            return Read(command, job.MediaSource?.Id, started);
        }
        catch (Exception) { return Unavailable(); }
    }

    internal OriginLogPhase Read(string command, string? source, DateTime start)
    {
        if ((_phases & (OriginLogPhase.Unavailable | OriginLogPhase.Progress)) != 0) return _phases;
        try
        {
            if (directory is null || !Path.IsPathFullyQualified(directory)) return Unavailable();
            if (command.Contains('\n') || command.Contains('\r') || command.Length > HeaderBytes
                || (_command is not null && _command != command)) return Unavailable();
            if (_path is null)
            {
                if (_samples++ % 3 != 0) return _phases;
                if (++_searches > MaximumSearches) return Unavailable();
                if (string.IsNullOrEmpty(source) || source.Length > 128
                    || source.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-' && c != '_')) return Unavailable();
                string? match = null; byte[]? matchedHeader = null;
                var candidates = 0;
                foreach (var candidate in Directory.EnumerateFiles(directory, $"FFmpeg.Transcode-*_{source}_*.log"))
                {
                    if (++candidates > MaximumCandidates) return Unavailable();
                    var info = new FileInfo(candidate);
                    if ((info.Attributes & FileAttributes.ReparsePoint) != 0
                        || Math.Abs((info.CreationTimeUtc - start).TotalSeconds) > 3) continue;
                    using var stream = Open(candidate);
                    var bytes = ReadBounded(stream, HeaderBytes);
                    // Jellyfin writes this exact command on its own line after
                    // the JSON media source. Merely matching a movie is unsafe.
                    if (!Encoding.UTF8.GetString(bytes).Split('\n')
                        .Any(line => line.TrimEnd('\r') == command)) continue;
                    if (match is not null) return Unavailable();
                    match = candidate; matchedHeader = bytes;
                }
                if (match is null) return _bytes >= MaximumBytes ? Unavailable() : _phases;
                _path = match; _command = command; _offset = matchedHeader!.Length;
                _created = File.GetCreationTimeUtc(_path);
                _phases |= OriginLogPhase.Attached;
                // Ignore all content before the exact command, including JSON
                // metadata that could contain text resembling an FFmpeg phase.
                Consume(matchedHeader, skipHeader: true);
                return _phases;
            }
            if ((File.GetAttributes(_path) & FileAttributes.ReparsePoint) != 0
                || File.GetCreationTimeUtc(_path) != _created) return Unavailable();
            using var tail = Open(_path);
            if (tail.Length < _offset) return Unavailable();
            tail.Position = _offset;
            var appended = ReadBounded(tail, ReadBytes);
            _offset += appended.Length;
            Consume(appended, skipHeader: false);
            return _bytes >= MaximumBytes && (_phases & OriginLogPhase.Progress) == 0 ? Unavailable() : _phases;
        }
        catch (Exception) { return Unavailable(); }
    }

    private static FileStream Open(string path) => new(path, FileMode.Open, FileAccess.Read,
        FileShare.ReadWrite | FileShare.Delete, 4096, FileOptions.SequentialScan);

    private byte[] ReadBounded(Stream stream, int maximum)
    {
        var bytes = new byte[Math.Min(maximum, MaximumBytes - _bytes)];
        var count = stream.Read(bytes);
        _bytes += count;
        return bytes[..count];
    }

    private void Consume(byte[] bytes, bool skipHeader)
    {
        foreach (var c in Encoding.UTF8.GetString(bytes))
        {
            if (c != '\n' && c != '\r')
            {
                if (_line.Length >= HeaderBytes) { Unavailable(); return; }
                _line.Append(c); continue;
            }
            var text = _line.ToString(); _line.Clear();
            if (skipHeader)
            {
                if (text == _command) skipHeader = false;
                continue;
            }
            _phases |= ParsePhase(text);
        }
    }

    internal static OriginLogPhase ParsePhase(string line)
    {
        if (line.StartsWith("libva info:", StringComparison.Ordinal)
            && line.EndsWith("va_openDriver() returns 0", StringComparison.Ordinal)) return OriginLogPhase.DriverOpened;
        if (line.StartsWith("Input #0,", StringComparison.Ordinal)) return OriginLogPhase.InputOpened;
        if (line == "Stream mapping:") return OriginLogPhase.StreamsMapped;
        if (line.StartsWith("Output #0, hls,", StringComparison.Ordinal)) return OriginLogPhase.OutputOpened;
        if (line.StartsWith("frame=", StringComparison.Ordinal) && line.Contains("time=", StringComparison.Ordinal)) return OriginLogPhase.Progress;
        return OriginLogPhase.None;
    }

    private OriginLogPhase Unavailable() { _phases |= OriginLogPhase.Unavailable; _line.Clear(); return _phases; }
}
