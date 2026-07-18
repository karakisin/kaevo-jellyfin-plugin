using System.Text.Json;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class PlaybackTrackCatalogTests
{
    [Fact]
    public void ReturnsOnlySanitizedSelectableTracks()
    {
        using var document = JsonDocument.Parse("""
        {
          "DefaultAudioStreamIndex": 2,
          "MediaStreams": [
            {"Type":"Video","Index":0,"DisplayTitle":"1080p","Path":"/private/movie.mkv"},
            {"Type":"Audio","Index":1,"DisplayTitle":"English 5.1","Language":"eng","Codec":"eac3","Channels":6,"IsDefault":false,"Path":"/private/movie.mkv"},
            {"Type":"Audio","Index":2,"DisplayTitle":"Spanish Stereo","Language":"spa","Codec":"aac","Channels":2,"IsDefault":true,"Path":"/private/movie.mkv"},
            {"Type":"Subtitle","Index":3,"DisplayTitle":"English","Language":"eng","Codec":"subrip","IsExternal":true,"IsTextSubtitleStream":true,"Path":"/private/movie.srt"}
          ]
        }
        """);

        var catalog = KaevoPlaybackTrackCatalog.FromMediaSource(document.RootElement);

        Assert.Equal(2, catalog.AudioTracks.Count);
        Assert.Single(catalog.SubtitleTracks);
        Assert.Equal(2, catalog.SelectedAudioStreamIndex);
        Assert.Equal("Spanish Stereo", catalog.AudioTracks[1].Title);
        Assert.True(catalog.SubtitleTracks[0].IsTextSubtitle);
        Assert.DoesNotContain("private", JsonSerializer.Serialize(catalog), StringComparison.OrdinalIgnoreCase);
    }
}
