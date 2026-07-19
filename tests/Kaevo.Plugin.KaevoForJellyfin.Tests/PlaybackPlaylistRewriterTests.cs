using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class PlaybackPlaylistRewriterTests
{
    private const string ItemId = "0123456789abcdef0123456789abcdef";
    private const string Grant = "signed-grant.token";

    [Fact]
    public void MasterPlaylistRewritesRelativeChildPlaylist()
    {
        var playlist = "#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=8000000\nhls1/main.m3u8?DeviceId=device-1\n";

        var rewritten = KaevoPlaybackPlaylistRewriter.Rewrite(
            playlist,
            Grant,
            ItemId,
            "source-1",
            $"/Videos/{ItemId}/master.m3u8?videoCodec=h264");

        Assert.Contains(
            "hls1/main.m3u8?DeviceId=device-1",
            rewritten,
            StringComparison.Ordinal);
        Assert.DoesNotContain(Grant, rewritten, StringComparison.Ordinal);
    }

    [Fact]
    public void MediaPlaylistRewritesFmp4MapAndSegments()
    {
        var playlist = "#EXTM3U\n#EXT-X-MAP:URI=\"main/-1.mp4?MediaSourceId=source-1\"\n#EXTINF:6.0,\nmain/0.mp4?PlaySessionId=session-1\n";

        var rewritten = KaevoPlaybackPlaylistRewriter.Rewrite(
            playlist,
            Grant,
            ItemId,
            "source-1",
            $"/Videos/{ItemId}/hls1/main.m3u8");

        Assert.Contains(
            "URI=\"main/-1.mp4?MediaSourceId=source-1\"",
            rewritten,
            StringComparison.Ordinal);
        Assert.Contains(
            "main/0.mp4?PlaySessionId=session-1",
            rewritten,
            StringComparison.Ordinal);
        Assert.DoesNotContain(Grant, rewritten, StringComparison.Ordinal);
    }

    [Fact]
    public void MasterPlaylistRewritesIndexedAlternateAudioRendition()
    {
        var playlist = "#EXTM3U\n#EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID=\"audio\",URI=\"hls1/audio/0.m3u8?MediaSourceId=source-1\"\n";

        var rewritten = KaevoPlaybackPlaylistRewriter.Rewrite(
            playlist,
            Grant,
            ItemId,
            "source-1",
            $"/Videos/{ItemId}/master.m3u8?audioCodec=aac");

        Assert.Contains(
            "URI=\"hls1/audio/0.m3u8?MediaSourceId=source-1\"",
            rewritten,
            StringComparison.Ordinal);
    }

    [Fact]
    public void AlternateAudioPlaylistRewritesNamedSegmentsInsideGrantedSession()
    {
        var playlist = "#EXTM3U\n#EXTINF:6.0,\naudio-00001.aac?PlaySessionId=session-1\n";

        var rewritten = KaevoPlaybackPlaylistRewriter.Rewrite(
            playlist,
            Grant,
            ItemId,
            "source-1",
            $"/Videos/{ItemId}/hls1/audio/0.m3u8");

        Assert.Contains(
            "audio-00001.aac?PlaySessionId=session-1",
            rewritten,
            StringComparison.Ordinal);
    }

    [Fact]
    public void SubtitleRenditionStaysInsideRelayAndDropsEmbeddedApiKey()
    {
        var playlist = $"#EXTM3U\n#EXT-X-MEDIA:TYPE=SUBTITLES,GROUP-ID=\"subs\",URI=\"source-1/Subtitles/4/subtitles.m3u8?SegmentLength=30&api_key=secret\"\n";

        var rewritten = KaevoPlaybackPlaylistRewriter.Rewrite(
            playlist,
            Grant,
            ItemId,
            "source-1",
            $"/Videos/{ItemId}/master.m3u8");

        Assert.Contains(
            "source-1/Subtitles/4/subtitles.m3u8?SegmentLength=30",
            rewritten,
            StringComparison.Ordinal);
        Assert.DoesNotContain("api_key", rewritten, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("secret", rewritten, StringComparison.Ordinal);
    }

    [Fact]
    public void JellyfinTrickplayRenditionStaysInsideRelayAndDropsEmbeddedApiKey()
    {
        var playlist = "#EXTM3U\n#EXT-X-IMAGE-STREAM-INF:BANDWIDTH=7603,RESOLUTION=320x160,CODECS=\"jpeg\",URI=\"Trickplay/320/tiles.m3u8?MediaSourceId=source-1&ApiKey=secret\"\n";

        var rewritten = KaevoPlaybackPlaylistRewriter.Rewrite(
            playlist,
            Grant,
            ItemId,
            "source-1",
            $"/Videos/{ItemId}/master.m3u8");

        Assert.Contains(
            "URI=\"Trickplay/320/tiles.m3u8?MediaSourceId=source-1\"",
            rewritten,
            StringComparison.Ordinal);
        Assert.DoesNotContain("ApiKey", rewritten, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("secret", rewritten, StringComparison.Ordinal);
    }

    [Fact]
    public void JellyfinTrickplayPlaylistRewritesOnlyNumberedJpegTiles()
    {
        var playlist = "#EXTM3U\n#EXTINF:1000,\n0.jpg?MediaSourceId=source-1&ApiKey=secret\n";

        var rewritten = KaevoPlaybackPlaylistRewriter.Rewrite(
            playlist,
            Grant,
            ItemId,
            "source-1",
            $"/Videos/{ItemId}/Trickplay/320/tiles.m3u8");

        Assert.Contains(
            "0.jpg?MediaSourceId=source-1",
            rewritten,
            StringComparison.Ordinal);
        Assert.DoesNotContain("ApiKey", rewritten, StringComparison.OrdinalIgnoreCase);
        Assert.Throws<InvalidOperationException>(() => KaevoPlaybackPlaylistRewriter.Rewrite(
            "#EXTM3U\nposter.jpg\n",
            Grant,
            ItemId,
            "source-1",
            $"/Videos/{ItemId}/Trickplay/320/tiles.m3u8"));
    }

    [Fact]
    public void FeatureLengthPlaylistDoesNotRepeatSignedGrantPerSegment()
    {
        var segments = string.Join('\n', Enumerable.Range(0, 2_400).Select(index =>
            $"#EXTINF:6.0,\nmain/{index:D5}.mp4?MediaSourceId=source-1&PlaySessionId=session-1"));
        var playlist = $"#EXTM3U\n{segments}\n#EXT-X-ENDLIST\n";

        var rewritten = KaevoPlaybackPlaylistRewriter.Rewrite(
            playlist,
            Grant,
            ItemId,
            "source-1",
            $"/Videos/{ItemId}/hls1/main.m3u8");

        Assert.DoesNotContain(Grant, rewritten, StringComparison.Ordinal);
        Assert.True(rewritten.Length <= playlist.Length);
        Assert.Contains("main/02399.mp4?MediaSourceId=source-1&PlaySessionId=session-1", rewritten, StringComparison.Ordinal);
    }

    [Fact]
    public void PlaylistRejectsExternalOrCrossItemUris()
    {
        Assert.Throws<InvalidOperationException>(() => KaevoPlaybackPlaylistRewriter.Rewrite(
            "#EXTM3U\nhttps://example.com/segment.ts\n",
            Grant,
            ItemId,
            "source-1",
            $"/Videos/{ItemId}/master.m3u8"));

        Assert.Throws<InvalidOperationException>(() => KaevoPlaybackPlaylistRewriter.Rewrite(
            "#EXTM3U\n/Videos/ffffffffffffffffffffffffffffffff/hls1/main/0.ts\n",
            Grant,
            ItemId,
            "source-1",
            $"/Videos/{ItemId}/master.m3u8"));
    }
}
