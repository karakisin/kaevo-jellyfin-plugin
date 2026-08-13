using System.Text.Json;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class PlaybackTrickplayCatalogTests
{
    [Fact]
    public void SelectsNearestBoundedWidthForExactMediaSource()
    {
        using var document = JsonDocument.Parse("""
        {
          "Trickplay": {
            "other-source": { "320": { "Width": 320, "Height": 180, "TileWidth": 10, "TileHeight": 10, "ThumbnailCount": 40, "Interval": 10000 } },
            "source-1": {
              "160": { "Width": 160, "Height": 90, "TileWidth": 10, "TileHeight": 10, "ThumbnailCount": 80, "Interval": 5000 },
              "320": { "Width": 320, "Height": 180, "TileWidth": 10, "TileHeight": 10, "ThumbnailCount": 40, "Interval": 10000 }
            }
          }
        }
        """);

        var metadata = KaevoPlaybackTrickplayCatalog.FromItem(document.RootElement, "source-1");

        Assert.NotNull(metadata);
        Assert.Equal(320, metadata.Width);
        Assert.Equal(180, metadata.Height);
        Assert.Equal(40, metadata.ThumbnailCount);
    }

    [Fact]
    public void RejectsAnotherSourceAndInvalidGeometry()
    {
        using var document = JsonDocument.Parse("""
        {
          "Trickplay": {
            "source-1": { "320": { "Width": 321, "Height": 180, "TileWidth": 10, "TileHeight": 10, "ThumbnailCount": 40, "Interval": 10000 } }
          }
        }
        """);

        Assert.Null(KaevoPlaybackTrickplayCatalog.FromItem(document.RootElement, "source-2"));
        Assert.Null(KaevoPlaybackTrickplayCatalog.FromItem(document.RootElement, "source-1"));
    }

    [Fact]
    public void SerializedMetadataContainsNoProviderPathOrCredential()
    {
        var metadata = new KaevoPlaybackTrickplayMetadata(320, 180, 10, 10, 40, 10000);
        var json = JsonSerializer.Serialize(metadata);

        Assert.Contains("\"width\":320", json);
        Assert.DoesNotContain("path", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("token", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("key", json, StringComparison.OrdinalIgnoreCase);
    }
}
