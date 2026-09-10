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
    [Theory]
    [InlineData(true, true, true, false, "direct_play")]
    [InlineData(false, true, true, false, "remux")]
    [InlineData(false, false, true, false, "transcode")]
    [InlineData(true, true, false, false, "remux")]
    [InlineData(true, true, true, true, "transcode")]
    public void ModeUsesNegotiatedCapabilityAndExplicitFallback(
        bool direct, bool remux, bool optedIn, bool force, string expected)
    {
        var source = JsonSerializer.SerializeToElement(new { SupportsDirectPlay = direct, SupportsDirectStream = remux });
        Assert.Equal(expected, KaevoPlaybackProfilePolicy.SelectMode(source, optedIn, force, false));
    }

    [Fact]
    public void NativeProfileRestrictsContainerAndUnsupportedVideoFormats()
    {
        var profile = JsonSerializer.SerializeToElement(KaevoPlaybackProfilePolicy.BuildAppleHlsDeviceProfile(24_000_000, true));
        Assert.Equal(24_000_000, profile.GetProperty("MaxStaticBitrate").GetInt32());
        var direct = profile.GetProperty("DirectPlayProfiles")[0];
        Assert.Equal("mp4,m4v,mov", direct.GetProperty("Container").GetString());
        Assert.Equal("h264,hevc", direct.GetProperty("VideoCodec").GetString());
        Assert.Equal("aac,ac3,eac3", direct.GetProperty("AudioCodec").GetString());
        var options = new JsonSerializerOptions();
        options.Converters.Add(new System.Text.Json.Serialization.JsonStringEnumConverter());
        var hevc = profile.GetProperty("CodecProfiles")[1].Deserialize<MediaBrowser.Model.Dlna.CodecProfile>(options)!;
        var range = Assert.Single(hevc.Conditions.Where(c => c.Property == MediaBrowser.Model.Dlna.ProfileConditionValue.VideoRangeType));
        Assert.True(range.IsRequired);
        Assert.Equal("SDR|HDR10|HLG", range.Value);
        bool Accepts(string videoProfile, int depth, Jellyfin.Data.Enums.VideoRangeType videoRange) =>
            hevc.Conditions.All(c => MediaBrowser.Model.Dlna.ConditionProcessor.IsVideoConditionSatisfied(
                c, 3840, 2160, depth, 20_000_000, videoProfile, videoRange, 153, 24,
                null, null, false, false, null, 1, 1, "hvc1", false));
        Assert.True(Accepts("Main 10", 10, Jellyfin.Data.Enums.VideoRangeType.HDR10));
        Assert.True(Accepts("Main", 8, Jellyfin.Data.Enums.VideoRangeType.SDR));
        Assert.False(Accepts("Main 12", 12, Jellyfin.Data.Enums.VideoRangeType.HDR10));
        Assert.False(Accepts("Main 10", 10, Jellyfin.Data.Enums.VideoRangeType.Unknown));
        Assert.False(Accepts("Main 10", 10, Enum.Parse<Jellyfin.Data.Enums.VideoRangeType>("DOVIWithHDR10")));

        var legacy = JsonSerializer.SerializeToElement(KaevoPlaybackProfilePolicy.BuildAppleHlsDeviceProfile(24_000_000));
        Assert.Equal(0, legacy.GetProperty("DirectPlayProfiles").GetArrayLength());
    }

}
