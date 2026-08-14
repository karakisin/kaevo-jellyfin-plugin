using System.Text.Json;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class MediaSegmentCatalogTests
{
    [Fact]
    public void ProjectsOnlyBoundedIntroAndRecapSegmentsForRequestedItem()
    {
        using var document = JsonDocument.Parse("""
        {
          "Items": [
            {"Id":"intro-1","ItemId":"episode-1","Type":"Intro","StartTicks":10000000,"EndTicks":710000000},
            {"Id":"recap-1","ItemId":"episode-1","Type":3,"StartTicks":0,"EndTicks":420000000},
            {"Id":"outro-1","ItemId":"episode-1","Type":"Outro","StartTicks":100,"EndTicks":200},
            {"Id":"wrong-item","ItemId":"episode-2","Type":"Intro","StartTicks":100,"EndTicks":200}
          ]
        }
        """);

        var result = KaevoMediaSegmentCatalog.FromJellyfin(document.RootElement, "episode-1");

        Assert.Equal(2, result.Count);
        Assert.Equal(new[] { "Intro", "Recap" }, result.Select(item => item.Type));
        Assert.All(result, item => Assert.Equal("episode-1", item.ItemId));
    }

    [Fact]
    public void RejectsInvertedOrUnreasonablyLongSegments()
    {
        using var document = JsonDocument.Parse("""
        {
          "Items": [
            {"ItemId":"episode-1","Type":"Intro","StartTicks":500,"EndTicks":400},
            {"ItemId":"episode-1","Type":"Recap","StartTicks":0,"EndTicks":18000000001}
          ]
        }
        """);

        Assert.Empty(KaevoMediaSegmentCatalog.FromJellyfin(document.RootElement, "episode-1"));
    }
}
