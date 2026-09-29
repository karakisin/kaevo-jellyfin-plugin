using Kaevo.Plugin.KaevoForJellyfin.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Text.RegularExpressions;

namespace Kaevo.Plugin.KaevoForJellyfin.Api;

[ApiController]
[Authorize]
[Route("Videos/{itemId}/hls99")]
public sealed class KaevoAudioSyncController : ControllerBase
{
    private readonly KaevoAudioSyncTranscoder _transcoder;
    public KaevoAudioSyncController(KaevoAudioSyncTranscoder transcoder) => _transcoder = transcoder;

    [HttpGet("main.m3u8")]
    [Produces("application/vnd.apple.mpegurl")]
    public async Task<IActionResult> Playlist(
        string itemId,
        [FromQuery] string playSessionId,
        [FromQuery] int audioOffsetMs,
        [FromQuery] int? audioStreamIndex,
        [FromQuery] long startTimeTicks = 0,
        CancellationToken cancellationToken = default)
    {
        var path = await _transcoder.PrepareAsync(itemId, playSessionId, audioOffsetMs, audioStreamIndex, startTimeTicks, cancellationToken)
            .ConfigureAwait(false);
        var playlist = await System.IO.File.ReadAllTextAsync(path, cancellationToken).ConfigureAwait(false);
        return Content(RewritePlaylist(playlist, playSessionId), "application/vnd.apple.mpegurl");
    }

    [HttpGet("{fileName}")]
    public IActionResult Segment(string fileName, [FromQuery] string playSessionId)
    {
        var path = _transcoder.SegmentPath(playSessionId, fileName);
        var contentType = fileName.EndsWith(".m4s", StringComparison.Ordinal) ? "video/iso.segment" : "video/mp4";
        return PhysicalFile(path, contentType, enableRangeProcessing: true);
    }

    internal static string RewritePlaylist(string playlist, string playSessionId)
    {
        var query = "?playSessionId=" + Uri.EscapeDataString(playSessionId);
        var withInitialization = Regex.Replace(
            playlist,
            "URI=\"(?<name>init\\.mp4)\"",
            match => $"URI=\"{match.Groups["name"].Value}{query}\"",
            RegexOptions.CultureInvariant);
        return string.Join('\n', withInitialization.Split('\n').Select(line =>
            line.StartsWith("segment", StringComparison.Ordinal) && line.EndsWith(".m4s", StringComparison.Ordinal)
                ? line + query
                : line));
    }
}
