using System.Text.Json;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class PlaybackProfilePolicyTests
{
    [Fact]
    public void RemoteBitrateUsesConfiguredAppleStreamingCeiling()
    {
        Assert.Equal(40_000_000, KaevoPlaybackProfilePolicy.ClampRemoteBitrate(50_000_000, null));
        Assert.Equal(24_000_000, KaevoPlaybackProfilePolicy.ClampRemoteBitrate(40_000_000, 24_000_000));
        Assert.Equal(12_000_000, KaevoPlaybackProfilePolicy.ClampRemoteBitrate(12_000_000, 30_000_000));
    }

    [Fact]
    public void AppleHlsProfileUsesFmp4AndAdvertisesHevcStreamCopy()
    {
        var profile = JsonSerializer.SerializeToElement(
            KaevoPlaybackProfilePolicy.BuildAppleHlsDeviceProfile(40_000_000));
        var transcode = profile.GetProperty("TranscodingProfiles")[0];

        Assert.Equal("mp4", transcode.GetProperty("Container").GetString());
        Assert.Equal("h264,hevc", transcode.GetProperty("VideoCodec").GetString());
        Assert.Equal("aac", transcode.GetProperty("AudioCodec").GetString());
        Assert.Equal("hls", transcode.GetProperty("Protocol").GetString());
    }
}
