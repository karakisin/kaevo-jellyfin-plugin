using System.Text.Json;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class PlaybackCompatibilityScannerTests
{
    [Fact]
    public void ProducesBoundedSanitizedCompatibilityRecommendations()
    {
        using var document = JsonDocument.Parse(JsonSerializer.Serialize(new
        {
            TotalRecordCount = 4,
            Items = new object[]
            {
                MediaItem("season-9", "Season 9", "h264", "aac"),
                MediaItem("season-11", "Season 11", "hevc", "aac"),
                MediaItem("movie-dts", "Movie DTS", "h264", "dts")
            }
        }));

        var result = JsonSerializer.SerializeToElement(
            KaevoPlaybackCompatibilityScanner.Scan(document.RootElement, 0, 3));

        Assert.True(result.GetProperty("bounded").GetBoolean());
        Assert.True(result.GetProperty("read_only").GetBoolean());
        Assert.False(result.GetProperty("execution_enabled").GetBoolean());
        Assert.True(result.GetProperty("has_more").GetBoolean());

        var items = result.GetProperty("items").EnumerateArray().ToArray();
        Assert.Equal("direct_play", items[0].GetProperty("recommendation").GetString());
        Assert.Equal("transcode_h264", items[1].GetProperty("recommendation").GetString());
        Assert.Equal("direct_play_requires_h264", items[1].GetProperty("reason").GetString());
        Assert.Equal(1920, items[1].GetProperty("width").GetInt32());
        Assert.Equal(1080, items[1].GetProperty("height").GetInt32());
        Assert.Equal(8_000_000, items[1].GetProperty("bitrate").GetInt32());
        Assert.Equal("transcode_audio", items[2].GetProperty("recommendation").GetString());

        var serialized = result.GetRawText();
        Assert.DoesNotContain("/media/", serialized, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Path", serialized, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void EpisodeTitleIncludesShowAndEpisodeNames()
    {
        using var document = JsonDocument.Parse(JsonSerializer.Serialize(new
        {
            TotalRecordCount = 1,
            Items = new[] { MediaItem("proposal", "The Proposal Proposal", "hevc", "aac", "The Big Bang Theory") }
        }));

        var result = JsonSerializer.SerializeToElement(KaevoPlaybackCompatibilityScanner.Scan(document.RootElement, 0, 10));
        var item = result.GetProperty("items")[0];

        Assert.Equal("The Big Bang Theory — The Proposal Proposal", item.GetProperty("title").GetString());
        Assert.Equal("The Big Bang Theory", item.GetProperty("show_name").GetString());
        Assert.Equal("The Proposal Proposal", item.GetProperty("episode_name").GetString());
    }

    [Theory]
    [InlineData("hevc", "eac3", "Main 10", 10, "yuv420p10le", "FullVideo")]
    [InlineData("hevc", "aac", "Main", 8, "yuv420p", "FullVideo")]
    [InlineData("h264", "eac3", "High", 8, "yuv420p", "AudioOnly")]
    [InlineData("vp9", "aac", "Profile 0", 8, "yuv420p", "FullVideo")]
    public void SelectsFastestSafeConversionStrategy(
        string videoCodec,
        string audioCodec,
        string profile,
        int bitDepth,
        string pixelFormat,
        string expected)
    {
        using var document = JsonDocument.Parse(JsonSerializer.Serialize(new
        {
            Id = "strategy-test",
            Name = "Strategy Test",
            Type = "Movie",
            MediaSources = new[]
            {
                new
                {
                    Container = "mp4",
                    MediaStreams = new object[]
                    {
                        new { Type = "Video", Codec = videoCodec, Profile = profile, BitDepth = bitDepth, PixelFormat = pixelFormat, Width = 3840, Height = 2160, BitRate = 18_900_000 },
                        new { Type = "Audio", Codec = audioCodec }
                    }
                }
            }
        }));

        Assert.Equal(expected, KaevoPlaybackCompatibilityScanner.SelectConversion(document.RootElement).Strategy.ToString());
    }

    [Fact]
    public void MissingStreamMetadataRequiresManualReview()
    {
        using var document = JsonDocument.Parse("""
        {
          "TotalRecordCount": 1,
          "Items": [{"Id":"unknown","Name":"Unknown","Type":"Movie","Path":"/private/movie.mkv"}]
        }
        """);

        var result = JsonSerializer.SerializeToElement(
            KaevoPlaybackCompatibilityScanner.Scan(document.RootElement, 0, 25));
        var item = result.GetProperty("items")[0];

        Assert.Equal("manual_review", item.GetProperty("recommendation").GetString());
        Assert.DoesNotContain("/private/movie.mkv", result.GetRawText(), StringComparison.Ordinal);
    }

    [Fact]
    public void DirectPlayPlanIsReadOnlyAndDoesNotExposePaths()
    {
        using var document = JsonDocument.Parse(JsonSerializer.Serialize(
            MediaItem("season-11", "Season 11", "hevc", "aac")));

        var plan = JsonSerializer.SerializeToElement(
            KaevoPlaybackCompatibilityScanner.PlanDirectPlay(document.RootElement));

        Assert.True(plan.GetProperty("eligible").GetBoolean());
        Assert.Equal("h264", plan.GetProperty("target").GetProperty("video_codec").GetString());
        Assert.Equal("aac", plan.GetProperty("target").GetProperty("audio_codec").GetString());
        Assert.True(plan.GetProperty("safety").GetProperty("read_only_plan").GetBoolean());
        Assert.False(plan.GetProperty("safety").GetProperty("execution_enabled").GetBoolean());
        Assert.DoesNotContain("/media/", plan.GetRawText(), StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Path", plan.GetRawText(), StringComparison.OrdinalIgnoreCase);
    }

    private static object MediaItem(string id, string title, string videoCodec, string audioCodec, string seriesName = "") => new
    {
        Id = id,
        Name = title,
        Type = "Episode",
        SeriesName = seriesName,
        Path = $"/media/{id}.mkv",
        MediaSources = new[]
        {
            new
            {
                Container = "mkv",
                Path = $"/media/{id}.mkv",
                MediaStreams = new object[]
                {
                    new { Type = "Video", Codec = videoCodec, Width = 1920, Height = 1080, BitRate = 8_000_000 },
                    new { Type = "Audio", Codec = audioCodec }
                }
            }
        }
    };
}
