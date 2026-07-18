using System.Text.Json;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class PlaybackSourcePolicyTests
{
    [Theory]
    [InlineData("iso", "/media/movie.iso", true)]
    [InlineData("", "/media/MOVIE.ISO", true)]
    [InlineData("mkv", "/media/movie.mkv", false)]
    public void DetectsDiscImagesWithoutExposingTheirPath(string container, string path, bool expected)
    {
        using var document = JsonDocument.Parse(JsonSerializer.Serialize(new { Container = container, Path = path }));

        Assert.Equal(expected, KaevoPlaybackSourcePolicy.IsDiscImage(document.RootElement));
    }
}
