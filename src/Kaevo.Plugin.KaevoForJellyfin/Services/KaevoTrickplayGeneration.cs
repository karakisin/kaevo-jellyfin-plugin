using System.Reflection;
using MediaBrowser.Model.Dto;
using System.Text.Json;
using MediaBrowser.Controller.Configuration;
using MediaBrowser.Controller.Entities;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.MediaEncoding;
using MediaBrowser.Controller.Trickplay;
using MediaBrowser.Model.Configuration;
using MediaBrowser.Model.Entities;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

public sealed record KaevoTrickplayJob(string ItemId, string State, string? Error = null);

/// Bounded explicit per-video generation. No library scan, metadata replacement,
/// media conversion, configuration changes, or caller-supplied filesystem paths.
public sealed class KaevoTrickplayGeneration
{
    private readonly object _gate = new();
    private readonly Dictionary<Guid, (KaevoTrickplayJob Job, DateTime Time)> _jobs = new();
    private readonly ILibraryManager _library;
    private readonly IMediaEncoder _encoder;
    private readonly ITrickplayManager _trickplay;
    private readonly EncodingHelper _encoding;
    private readonly IServerConfigurationManager _config;
    private readonly IHostApplicationLifetime _lifetime;
    private readonly ILogger<KaevoTrickplayGeneration> _logger;
    private Guid? _active;

    public KaevoTrickplayGeneration(ILibraryManager library, IMediaEncoder encoder,
        ITrickplayManager trickplay, EncodingHelper encoding, IServerConfigurationManager config,
        IHostApplicationLifetime lifetime, ILogger<KaevoTrickplayGeneration> logger)
    {
        _library = library; _encoder = encoder; _trickplay = trickplay; _encoding = encoding;
        _config = config; _lifetime = lifetime; _logger = logger;
    }

    public KaevoTrickplayJob Queue(string itemId)
    {
        var id = ParseItem(itemId);
        var video = _library.GetItemById(id) as Video
            ?? throw new InvalidOperationException("trickplayVideoRequired");
        ValidateVideo(video);
        lock (_gate)
        {
            if (_jobs.TryGetValue(id, out var existing)
                && (existing.Job.State is "queued" or "running" || DateTime.UtcNow - existing.Time < TimeSpan.FromMinutes(1)))
                return existing.Job;
            if (_active is not null) throw new InvalidOperationException("trickplayServerBusy");
            foreach (var key in _jobs.Where(p => DateTime.UtcNow - p.Value.Time > TimeSpan.FromHours(24)).Select(p => p.Key).ToArray())
                _jobs.Remove(key);
            if (_jobs.Count >= 128) _jobs.Remove(_jobs.MinBy(p => p.Value.Time).Key);
            _active = id;
            var job = new KaevoTrickplayJob(id.ToString("N"), "queued");
            _jobs[id] = (job, DateTime.UtcNow);
            _ = Task.Run(() => RunAsync(id, video.Path));
            return job;
        }
    }

    public KaevoTrickplayJob Status(string itemId)
    {
        var id = ParseItem(itemId);
        if (_library.GetItemById(id) is not Video) throw new InvalidOperationException("trickplayVideoRequired");
        lock (_gate) return _jobs.TryGetValue(id, out var value) ? value.Job : new(id.ToString("N"), "idle");
    }

    internal static Guid ParseItem(string? value) => value?.Length == 32 && Guid.TryParseExact(value, "N", out var id)
        && id != Guid.Empty ? id : throw new InvalidOperationException("trickplayItemInvalid");

    internal static void ValidateVideo(Video video)
    {
        if (video.IsPlaceHolder || video.IsShortcut || !video.IsCompleteMedia
            || string.IsNullOrWhiteSpace(video.Path) || !Path.IsPathFullyQualified(video.Path)
            || (!File.Exists(video.Path) && !Directory.Exists(video.Path)))
            throw new InvalidOperationException("trickplaySourceUnavailable");
        if (video.RunTimeTicks is not long ticks || ticks <= 0 || ticks > TimeSpan.FromHours(12).Ticks)
            throw new InvalidOperationException("trickplayDurationUnsupported");
    }

    private void Set(Guid id, string state, string? error = null)
    {
        lock (_gate) _jobs[id] = (new(id.ToString("N"), state, error), DateTime.UtcNow);
        _logger.LogInformation("Kaevo per-video trickplay item={ItemId} state={State} reason={Reason}", id, state, error);
    }

    private async Task RunAsync(Guid id, string originalPath)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.ApplicationStopping);
        timeout.CancelAfter(TimeSpan.FromMinutes(30));
        try
        {
            Set(id, "running");
            await GenerateAsync(id, originalPath, timeout.Token).ConfigureAwait(false);
            Set(id, "complete");
        }
        catch (OperationCanceledException) { Set(id, "failed", "trickplayGenerationInterrupted"); }
        catch (Exception ex)
        {
            var cause = ex is TargetInvocationException { InnerException: not null } tie ? tie.InnerException! : ex;
            // Do not publish provider paths, process arguments or credentials.
            var code = cause is UnauthorizedAccessException ? "trickplayStoragePermissionDenied"
                : cause is InvalidOperationException && cause.Message.StartsWith("trickplay", StringComparison.Ordinal)
                    ? cause.Message : "trickplayGenerationFailed";
            Set(id, "failed", code);
            _logger.LogWarning("Kaevo per-video trickplay failed type={Type}", cause.GetType().Name);
            if (cause is MissingMethodException) _logger.LogWarning("Kaevo trickplay runtime contract: {Method}", cause.Message);
        }
        finally { lock (_gate) _active = null; }
    }

    private async Task GenerateAsync(Guid id, string originalPath, CancellationToken token)
    {
        var video = CurrentVideo(id, originalPath);
        var library = _library.GetLibraryOptions(video) ?? throw new InvalidOperationException("trickplayLibraryUnavailable");
        // A private copy prevents normalized extraction values from mutating global settings.
        var options = JsonSerializer.Deserialize<TrickplayOptions>(JsonSerializer.Serialize(_config.Configuration.TrickplayOptions))
            ?? throw new InvalidOperationException("trickplayConfigurationInvalid");
        ValidateOptions(options, video.RunTimeTicks!.Value);
        var sources = video.GetType().GetMethod("GetMediaSources", new[] { typeof(bool) })?.Invoke(video, new object[] { false })
            as IEnumerable<MediaSourceInfo> ?? throw new InvalidOperationException("trickplayServerVersionUnsupported");
        var source = sources.SingleOrDefault(s => string.Equals(s.Id, id.ToString("N"), StringComparison.OrdinalIgnoreCase)
            && string.Equals(s.Path, video.Path, StringComparison.Ordinal) && !s.IsRemote)
            ?? throw new InvalidOperationException("trickplaySourceAmbiguous");
        var stream = source.VideoStream ?? source.MediaStreams.FirstOrDefault(s => s.Type == MediaStreamType.Video)
            ?? throw new InvalidOperationException("trickplayVideoStreamMissing");
        var width = options.WidthResolutions.OrderBy(w => Math.Abs(w - 320)).First();
        if (stream.Width is int sourceWidth) width = Math.Min(width, sourceWidth / 2 * 2);
        if (width < 2) throw new InvalidOperationException("trickplayConfigurationInvalid");
        ValidateGeometry(width, stream.Width, stream.Height, options, video.RunTimeTicks!.Value);
        string? imagesDir = null;
        string? staging = null;
        string? backup = null;
        var output = _trickplay.GetTrickplayDirectory(video, options.TileWidth, options.TileHeight, width, library.SaveTrickplayWithMedia);
        var installed = false;
        try
        {
            // Uses Jellyfin's existing encoding settings and disc input handling.
            // Unlike RefreshTrickplayDataAsync, this does not silently skip disc media.
            imagesDir = await _encoder.ExtractVideoImagesOnIntervalAccelerated(video.Path, source.Container,
                source, stream, width, TimeSpan.FromMilliseconds(options.Interval), options.EnableHwAcceleration,
                options.EnableHwEncoding, options.ProcessThreads, options.Qscale, options.ProcessPriority,
                options.EnableKeyFrameOnlyExtraction, _encoding, token).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            CurrentVideo(id, originalPath);
            var images = Directory.GetFiles(imagesDir, "*.jpg").OrderBy(p => p, StringComparer.Ordinal).ToArray();
            ValidateFrameCount(images.Length, video.RunTimeTicks!.Value, options.Interval);
            staging = output + ".kaevo-" + Guid.NewGuid().ToString("N");
            // TrickplayInfo moved assemblies in Jellyfin 10.11. Invoke these two
            // public methods by their exact runtime signatures, not a pinned DTO.
            var create = _trickplay.GetType().GetMethod("CreateTiles", new[] { typeof(IReadOnlyList<string>), typeof(int), typeof(TrickplayOptions), typeof(string) })
                ?? throw new InvalidOperationException("trickplayServerVersionUnsupported");
            var info = create.Invoke(_trickplay, new object[] { images, width, options, staging })
                ?? throw new InvalidOperationException("trickplayNoFramesProduced");
            var itemProperty = info.GetType().GetProperty("ItemId")
                ?? throw new InvalidOperationException("trickplayServerVersionUnsupported");
            var save = _trickplay.GetType().GetMethod("SaveTrickplayInfo", new[] { info.GetType() })
                ?? throw new InvalidOperationException("trickplayServerVersionUnsupported");
            itemProperty.SetValue(info, id);
            token.ThrowIfCancellationRequested();
            CurrentVideo(id, originalPath);
            if (_library.GetLibraryOptions(video)?.SaveTrickplayWithMedia != library.SaveTrickplayWithMedia)
                throw new InvalidOperationException("trickplayLibraryChanged");
            if (Directory.Exists(output))
            {
                backup = output + ".kaevo-backup-" + Guid.NewGuid().ToString("N");
                Directory.Move(output, backup);
            }
            Directory.Move(staging, output);
            installed = true;
            var expectedTiles = (images.Length + options.TileWidth * options.TileHeight - 1) / (options.TileWidth * options.TileHeight);
            for (var index = 0; index < expectedTiles; index++)
            {
                var generatedTile = Path.Combine(output, index + ".jpg");
                if (!File.Exists(generatedTile) || new FileInfo(generatedTile).Length == 0)
                    throw new InvalidOperationException("trickplayReadbackFailed");
            }
            // SaveTrickplayInfo commits native metadata in one transaction.
            // Before that commit, any failure restores the previous tile set.
            await ((Task?)save.Invoke(_trickplay, new[] { info })
                ?? throw new InvalidOperationException("trickplayServerVersionUnsupported")).ConfigureAwait(false);
            installed = false;
            Cleanup(backup);
            backup = null;
            var tile = await _trickplay.GetTrickplayTilePathAsync(video, width, 0, library.SaveTrickplayWithMedia).ConfigureAwait(false);
            if (!File.Exists(tile) || new FileInfo(tile).Length == 0) throw new InvalidOperationException("trickplayReadbackFailed");
        }
        catch
        {
            if (installed && Directory.Exists(output)) Directory.Delete(output, true);
            if (backup is not null && Directory.Exists(backup)) { Directory.Move(backup, output); backup = null; }
            throw;
        }
        finally
        {
            Cleanup(imagesDir);
            Cleanup(staging);
        }
    }

    private void Cleanup(string? path)
    {
        try { if (path is not null && Directory.Exists(path)) Directory.Delete(path, true); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        { _logger.LogWarning("Kaevo trickplay temporary cleanup deferred type={Type}", ex.GetType().Name); }
    }

    internal static void ValidateGeometry(int width, int? sourceWidth, int? sourceHeight, TrickplayOptions options, long duration)
    {
        if (sourceWidth is null or <= 0 || sourceHeight is null or <= 0)
            throw new InvalidOperationException("trickplayVideoGeometryMissing");
        var height = Math.Ceiling(width * (double)sourceHeight.Value / sourceWidth.Value);
        var pixels = width * height;
        var frames = Math.Ceiling(duration / (double)TimeSpan.TicksPerMillisecond / options.Interval);
        if (!double.IsFinite(pixels) || height > 1920 || pixels * options.TileWidth * options.TileHeight > 32_000_000
            || pixels * frames > 1_000_000_000)
            throw new InvalidOperationException("trickplayConfigurationInvalid");
    }

    internal static void ValidateFrameCount(int count, long duration, int interval)
    {
        // Permit one boundary-frame rounding difference, never silently publish
        // an early decoder failure as a complete film's preview set.
        var expected = (int)Math.Ceiling(duration / (double)TimeSpan.TicksPerMillisecond / interval);
        if (count < Math.Max(1, expected - 1) || count > expected + 1 || count > 10_000)
            throw new InvalidOperationException("trickplayIncompleteFrames");
    }

    private Video CurrentVideo(Guid id, string path)
    {
        if (_library.GetItemById(id) is not Video video || video.Path != path)
            throw new InvalidOperationException("trickplayItemChanged");
        ValidateVideo(video);
        return video;
    }

    internal static void ValidateOptions(TrickplayOptions value, long duration)
    {
        if (value.Interval < 1_000 || value.Interval > 3_600_000 || value.TileWidth is < 1 or > 20
            || value.TileHeight is < 1 or > 20 || value.WidthResolutions is null || value.WidthResolutions.Length == 0
            || value.WidthResolutions.Any(w => w is < 2 or > 1920)
            || duration / (double)TimeSpan.TicksPerMillisecond / value.Interval > 10_000)
            throw new InvalidOperationException("trickplayConfigurationInvalid");
    }
}
