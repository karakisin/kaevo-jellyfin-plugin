using System.Reflection;
using System.Text.Json;
using Kaevo.Plugin.KaevoForJellyfin.Api;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using MediaBrowser.Model.Configuration;
using Microsoft.AspNetCore.Authorization;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class TrickplayGenerationTests
{
    [Theory]
    [InlineData(null)] [InlineData("")] [InlineData("00000000000000000000000000000000")]
    [InlineData("../../other")] [InlineData("12345678-1234-1234-1234-123456789012")]
    public void InvalidOrPathLikeItemIsRejected(string? item) =>
        Assert.Throws<InvalidOperationException>(() => KaevoTrickplayGeneration.ParseItem(item));

    [Fact]
    public void GenerationRequiresElevatedJellyfinIdentity()
    {
        var auth = typeof(KaevoTrickplayController).GetCustomAttribute<AuthorizeAttribute>();
        Assert.Equal("RequiresElevation", auth?.Policy);
        Assert.False(KaevoTrickplayController.MatchesServer(null, "server-a"));
        Assert.False(KaevoTrickplayController.MatchesServer("server-b", "server-a"));
        Assert.True(KaevoTrickplayController.MatchesServer("server-a", "server-a"));
    }

    [Theory]
    [InlineData(0)] [InlineData(2)] [InlineData(10001)]
    public void IncompleteOrUnboundedFramesAreNotCompletion(int frames) =>
        Assert.Throws<InvalidOperationException>(() => KaevoTrickplayGeneration.ValidateFrameCount(frames, TimeSpan.FromSeconds(45).Ticks, 10000));

    [Theory]
    [InlineData(4)] [InlineData(5)] [InlineData(6)]
    public void FrameBoundaryRoundingIsAccepted(int frames) =>
        KaevoTrickplayGeneration.ValidateFrameCount(frames, TimeSpan.FromSeconds(45).Ticks, 10000);

    [Fact]
    public void UnsafeResourceSettingsAreRejectedWithoutChangingThem()
    {
        var options = new TrickplayOptions { Interval = 10000, TileWidth = 10, TileHeight = 10, WidthResolutions = new[] { 320 } };
        KaevoTrickplayGeneration.ValidateOptions(options, TimeSpan.FromMinutes(90).Ticks);
        options.Interval = 0;
        Assert.Throws<InvalidOperationException>(() => KaevoTrickplayGeneration.ValidateOptions(options, TimeSpan.FromMinutes(90).Ticks));
        Assert.Equal(0, options.Interval);
        options.Interval = 1000;
        Assert.Throws<InvalidOperationException>(() => KaevoTrickplayGeneration.ValidateOptions(options, TimeSpan.FromHours(12).Ticks));
        options.Interval = 10000; options.TileWidth = 1000;
        Assert.Throws<InvalidOperationException>(() => KaevoTrickplayGeneration.ValidateOptions(options, TimeSpan.FromMinutes(90).Ticks));
    }
    [Fact]
    public void OversizedMosaicOrTotalFrameWorkIsRejected()
    {
        var options = new TrickplayOptions { Interval = 10000, TileWidth = 10, TileHeight = 10, WidthResolutions = new[] { 320 } };
        KaevoTrickplayGeneration.ValidateGeometry(320, 1920, 1080, options, TimeSpan.FromHours(2).Ticks);
        Assert.Throws<InvalidOperationException>(() => KaevoTrickplayGeneration.ValidateGeometry(1920, 1920, 1080, options, TimeSpan.FromHours(2).Ticks));
        Assert.Throws<InvalidOperationException>(() => KaevoTrickplayGeneration.ValidateGeometry(320, 1, 10000, options, TimeSpan.FromHours(2).Ticks));
        Assert.Throws<InvalidOperationException>(() => KaevoTrickplayGeneration.ValidateGeometry(320, null, 1080, options, TimeSpan.FromHours(2).Ticks));
    }

    [Fact]
    public void CloudStatusCannotAttachToAnotherItemOrExceedResponseLimit()
    {
        const string id = "0123456789abcdef0123456789abcdef";
        var source = JsonSerializer.SerializeToElement(new { Id = id, Name = "Fixture" });
        var job = new KaevoTrickplayJob(id, "running");
        Assert.True(KaevoCloudConnectorService.WithTrickplayJob(source, job, 4096).TryGetProperty("KaevoTrickplayJob", out _));
        Assert.False(KaevoCloudConnectorService.WithTrickplayJob(source, job with { ItemId = new string('a', 32) }, 4096).TryGetProperty("KaevoTrickplayJob", out _));
        Assert.False(KaevoCloudConnectorService.WithTrickplayJob(source, job, 10).TryGetProperty("KaevoTrickplayJob", out _));
        Assert.Equal(source.GetRawText(), KaevoCloudConnectorService.WithTrickplayJob(source, job, 10).GetRawText());
    }

}
