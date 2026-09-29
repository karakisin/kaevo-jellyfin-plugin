using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class AudioSyncTranscoderTests
{
    [Theory]
    [InlineData(false, false, true, true, "direct_play")]
    [InlineData(false, true, true, true, "transcode")]
    [InlineData(true, false, true, true, "transcode")]
    [InlineData(false, false, false, true, "remux")]
    [InlineData(false, false, false, false, "transcode")]
    public void PlaybackModeHonorsForcedCompatibility(
        bool hasAudioOffset,
        bool forceTranscoding,
        bool preferDirectPlay,
        bool supportsDirectStream,
        string expected)
    {
        Assert.Equal(expected, KaevoCloudConnectorService.PlaybackMode(
            hasAudioOffset,
            forceTranscoding,
            preferDirectPlay,
            supportsDirectStream));
    }

    [Theory]
    [InlineData(250, "asetpts=PTS+0.25/TB")]
    [InlineData(-750, "asetpts=PTS-0.75/TB")]
    [InlineData(50, "asetpts=PTS+0.05/TB")]
    public void AudioFilterMovesOnlyAudioTimestamps(int offsetMilliseconds, string expected)
    {
        Assert.Equal(expected, KaevoAudioSyncTranscoder.AudioFilter(offsetMilliseconds));
    }

    [Fact]
    public void PlaylistResourcesRetainPlaybackSessionBinding()
    {
        const string source = "#EXTM3U\n#EXT-X-MAP:URI=\"init.mp4\"\n#EXTINF:2,\nsegment000001.m4s\n";
        var result = Api.KaevoAudioSyncController.RewritePlaylist(source, "session:1");
        Assert.Contains("URI=\"init.mp4?playSessionId=session%3A1\"", result);
        Assert.Contains("segment000001.m4s?playSessionId=session%3A1", result);
    }
}
