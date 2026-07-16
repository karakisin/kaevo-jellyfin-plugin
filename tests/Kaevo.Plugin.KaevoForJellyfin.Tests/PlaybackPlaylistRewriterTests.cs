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
            $"/Videos/{ItemId}/master.m3u8?videoCodec=h264");

        Assert.Contains(
            $"/v1/playback/{Grant}/Videos/{ItemId}/hls1/main.m3u8?DeviceId=device-1",
            rewritten,
            StringComparison.Ordinal);
    }

    [Fact]
    public void MediaPlaylistRewritesFmp4MapAndSegments()
    {
        var playlist = "#EXTM3U\n#EXT-X-MAP:URI=\"main/-1.mp4?MediaSourceId=source-1\"\n#EXTINF:6.0,\nmain/0.mp4?PlaySessionId=session-1\n";

        var rewritten = KaevoPlaybackPlaylistRewriter.Rewrite(
            playlist,
            Grant,
            ItemId,
            $"/Videos/{ItemId}/hls1/main.m3u8");

        Assert.Contains(
            $"URI=\"/v1/playback/{Grant}/Videos/{ItemId}/hls1/main/-1.mp4?MediaSourceId=source-1\"",
            rewritten,
            StringComparison.Ordinal);
        Assert.Contains(
            $"/v1/playback/{Grant}/Videos/{ItemId}/hls1/main/0.mp4?PlaySessionId=session-1",
            rewritten,
            StringComparison.Ordinal);
    }

    [Fact]
    public void MasterPlaylistRewritesIndexedAlternateAudioRendition()
    {
        var playlist = "#EXTM3U\n#EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID=\"audio\",URI=\"hls1/audio/0.m3u8?MediaSourceId=source-1\"\n";

        var rewritten = KaevoPlaybackPlaylistRewriter.Rewrite(
            playlist,
            Grant,
            ItemId,
            $"/Videos/{ItemId}/master.m3u8?audioCodec=aac");

        Assert.Contains(
            $"URI=\"/v1/playback/{Grant}/Videos/{ItemId}/hls1/audio/0.m3u8?MediaSourceId=source-1\"",
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
            $"/Videos/{ItemId}/hls1/audio/0.m3u8");

        Assert.Contains(
            $"/v1/playback/{Grant}/Videos/{ItemId}/hls1/audio/audio-00001.aac?PlaySessionId=session-1",
            rewritten,
            StringComparison.Ordinal);
    }

    [Fact]
    public void PlaylistRejectsExternalOrCrossItemUris()
    {
        Assert.Throws<InvalidOperationException>(() => KaevoPlaybackPlaylistRewriter.Rewrite(
            "#EXTM3U\nhttps://example.com/segment.ts\n",
            Grant,
            ItemId,
            $"/Videos/{ItemId}/master.m3u8"));

        Assert.Throws<InvalidOperationException>(() => KaevoPlaybackPlaylistRewriter.Rewrite(
            "#EXTM3U\n/Videos/ffffffffffffffffffffffffffffffff/hls1/main/0.ts\n",
            Grant,
            ItemId,
            $"/Videos/{ItemId}/master.m3u8"));
    }
}
