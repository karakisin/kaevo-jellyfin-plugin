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
    [InlineData(250, "asetpts=PTS-STARTPTS,adelay=250:all=1")]
    [InlineData(-750, "atrim=start=0.75,asetpts=PTS-STARTPTS")]
    [InlineData(50, "asetpts=PTS-STARTPTS,adelay=50:all=1")]
    public void AudioFilterPadsOrTrimsAudioWithoutMovingVideoClock(int offsetMilliseconds, string expected)
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
