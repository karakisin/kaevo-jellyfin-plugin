using System.Text.Json;
using System.Text.Json.Serialization;
using Jellyfin.Data.Enums;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using MediaBrowser.Model.Dlna;
using MediaBrowser.Model.Dto;
using MediaBrowser.Model.Entities;
using MediaBrowser.Model.MediaInfo;
using MediaBrowser.Model.Session;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class PlaybackSubtitleNegotiationTests
{
    [Theory]
    [InlineData("aac")]
    [InlineData("dts")]
    public void SegmentedProfilePreservesSelectedLanguageAndConvertsIncompatibleAudio(string codec)
    {
        var json = new JsonSerializerOptions();
        json.Converters.Add(new JsonStringEnumConverter());
        var profile = JsonSerializer.Deserialize<DeviceProfile>(JsonSerializer.Serialize(
            KaevoPlaybackProfilePolicy.BuildAppleHlsDeviceProfile(40_000_000, true)), json)!;
        var source = new MediaSourceInfo {
            Id = "prepared-source", Container = "mp4", Protocol = MediaProtocol.File,
            SupportsDirectPlay = true, SupportsDirectStream = true, SupportsTranscoding = true,
            Bitrate = 4_256_000, DefaultAudioStreamIndex = 1,
            MediaStreams = new [] {
                new MediaStream { Index = 0, Type = MediaStreamType.Video, Codec = "h264", Profile = "High", Level = 40, BitDepth = 8, Width = 1280, Height = 720, BitRate = 4_000_000 },
                new MediaStream { Index = 1, Type = MediaStreamType.Audio, Codec = codec, Profile = "LC", Channels = 2, SampleRate = 48000, BitRate = 128000, IsDefault = true, Language = "por" },
                new MediaStream { Index = 2, Type = MediaStreamType.Audio, Codec = codec, Profile = "LC", Channels = 2, SampleRate = 48000, BitRate = 128000, Language = "eng" }
            }
        };
        var result = new StreamBuilder(new Encoder(), NullLogger.Instance).GetOptimalVideoStream(new MediaOptions {
            ItemId = Guid.NewGuid(), DeviceId = "test-device", Profile = profile,
            MediaSources = new [] { source }, MediaSourceId = source.Id,
            MaxBitrate = 40_000_000, EnableDirectPlay = false, EnableDirectStream = true,
            AllowAudioStreamCopy = true, AllowVideoStreamCopy = true,
            AudioStreamIndex = 2, SubtitleStreamIndex = -1
        });
        Assert.NotNull(result);
        Assert.Equal(PlayMethod.DirectStream, result.PlayMethod);
        Assert.Contains("h264", result.VideoCodecs);
        Assert.Contains("aac", result.AudioCodecs);
        Assert.DoesNotContain("dts", result.AudioCodecs);
        Assert.Equal(2, result.AudioStreamIndex);
    }

    [Theory]
    [InlineData(null, PlayMethod.Transcode)]
    [InlineData(-1, PlayMethod.DirectPlay)]
    [InlineData(0, PlayMethod.Transcode)]
    public void ProviderDefaultSubtitleMustNotOverrideAnExplicitOffSelection(int? selection, PlayMethod expected)
    {
        var json = new JsonSerializerOptions();
        json.Converters.Add(new JsonStringEnumConverter());
        var profile = JsonSerializer.Deserialize<DeviceProfile>(JsonSerializer.Serialize(
            KaevoPlaybackProfilePolicy.BuildAppleHlsDeviceProfile(40_000_000, true)), json)!;
        var source = new MediaSourceInfo {
            Id = "episode-source", Container = "mp4", Protocol = MediaProtocol.File,
            SupportsDirectPlay = true, SupportsDirectStream = true, SupportsTranscoding = true,
            Bitrate = 7_184_085, DefaultAudioStreamIndex = 2, DefaultSubtitleStreamIndex = 0,
            MediaStreams = new [] {
                new MediaStream { Index = 0, Type = MediaStreamType.Subtitle, Codec = "subrip", IsExternal = true },
                new MediaStream { Index = 1, Type = MediaStreamType.Video, Codec = "h264", Profile = "High", Level = 40, BitDepth = 8, Width = 1920, Height = 1080, BitRate = 6_947_000 },
                new MediaStream { Index = 2, Type = MediaStreamType.Audio, Codec = "aac", Profile = "LC", Channels = 2, SampleRate = 44100, BitRate = 128000, IsDefault = true }
            }
        };
        var result = new StreamBuilder(new Encoder(), NullLogger.Instance).GetOptimalVideoStream(new MediaOptions {
            ItemId = Guid.NewGuid(), DeviceId = "test-device", Profile = profile,
            MediaSources = new [] { source }, MediaSourceId = source.Id,
            MaxBitrate = 40_000_000, EnableDirectPlay = true, EnableDirectStream = false,
            AllowAudioStreamCopy = false, AllowVideoStreamCopy = true,
            SubtitleStreamIndex = selection
        });
        Assert.NotNull(result);
        Assert.Equal(expected, result.PlayMethod);
        if (selection != -1)
            Assert.True(result.TranscodeReasons.HasFlag(TranscodeReason.SubtitleCodecNotSupported));
    }
    [Fact]
    public void NegotiationUsesTheAuthorizedSourceAndPreservesExplicitSubtitles()
    {
        var item = JsonSerializer.SerializeToElement(new { Id = "item-id", MediaSources = new[] { new { Id = "source-id" } } });
        var off = KaevoPlaybackNegotiationPolicy.FromAuthorizedItem(item, null);
        Assert.Equal("source-id", off.MediaSourceId);
        Assert.Equal(-1, off.SubtitleStreamIndex);
        Assert.Equal(0, KaevoPlaybackNegotiationPolicy.FromAuthorizedItem(item, 0).SubtitleStreamIndex);
        Assert.Throws<InvalidOperationException>(() => KaevoPlaybackNegotiationPolicy.FromAuthorizedItem(JsonSerializer.SerializeToElement(new { Id = "item-id" }), null));
        Assert.Throws<InvalidOperationException>(() => KaevoPlaybackNegotiationPolicy.FromAuthorizedItem(JsonSerializer.SerializeToElement(new { MediaSources = new[] { new { Id = "../other" } } }), null));
    }
    [Theory]
    [InlineData("null")]
    [InlineData("{\"MediaSources\":[null]}")]
    [InlineData("{\"MediaSources\":[]}")]
    [InlineData("{\"MediaSources\":[{\"Id\":\"\"}]}")]
    public void InvalidAuthorizedSourcesFailClosed(string json)
    {
        using var document = JsonDocument.Parse(json);
        Assert.Throws<InvalidOperationException>(() =>
            KaevoPlaybackNegotiationPolicy.FromAuthorizedItem(document.RootElement, null));
    }

    private sealed class Encoder : ITranscoderSupport {
        public bool CanEncodeToAudioCodec(string codec) => true;
        public bool CanEncodeToSubtitleCodec(string codec) => true;
        public bool CanExtractSubtitles(string codec) => true;
    }
}
