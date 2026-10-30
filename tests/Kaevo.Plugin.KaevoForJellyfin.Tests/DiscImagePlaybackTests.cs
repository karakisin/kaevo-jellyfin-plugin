using System.Net;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Kaevo.Plugin.KaevoForJellyfin.Configuration;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class DiscImagePlaybackTests
{
    private const string Item = "0123456789abcdef0123456789abcdef";
    private const string User = "11111111111111111111111111111111";
    private const BindingFlags PrivateInstance = BindingFlags.Instance | BindingFlags.NonPublic;

    private static JsonObject Source() => new()
    {
        ["Id"] = "disc-source", ["Container"] = "iso", ["Path"] = "/private/library/test.iso",
        ["SupportsTranscoding"] = true, ["SupportsDirectStream"] = true, ["SupportsDirectPlay"] = true,
        ["TranscodingSubProtocol"] = "hls", ["TranscodingContainer"] = "mp4",
        ["TranscodingUrl"] = $"/Videos/{Item}/master.m3u8?api_key=must-not-leak",
        ["DefaultAudioStreamIndex"] = 1, ["MediaStreams"] = new JsonArray()
    };
    private static JsonElement Element(JsonNode node) => JsonSerializer.SerializeToElement(node);

    [Theory]
    [InlineData(false, false, false, "remux")]
    [InlineData(false, true, false, "remux")]
    [InlineData(true, false, false, "remux")]
    [InlineData(true, true, false, "remux")]
    [InlineData(false, false, true, "transcode")]
    [InlineData(false, true, true, "transcode")]
    [InlineData(true, false, true, "transcode")]
    [InlineData(true, true, true, "transcode")]
    public void DiscNeverUsesRawDirectPlay(bool preferDirect, bool compatibility, bool force, string expected)
    {
        Assert.Equal(expected, KaevoPlaybackProfilePolicy.SelectMode(Element(Source()), preferDirect, force, compatibility));
    }

    [Theory]
    [InlineData("SupportsTranscoding", "false")]
    [InlineData("SupportsTranscoding", "\"true\"")]
    [InlineData("SupportsTranscoding", "null")]
    [InlineData("TranscodingSubProtocol", "\"http\"")]
    [InlineData("TranscodingSubProtocol", "0")]
    [InlineData("TranscodingSubProtocol", "null")]
    [InlineData("TranscodingContainer", "\"iso\"")]
    [InlineData("TranscodingContainer", "\"mkv\"")]
    [InlineData("TranscodingContainer", "null")]
    [InlineData("TranscodingUrl", "\"\"")]
    [InlineData("TranscodingUrl", "null")]
    [InlineData("TranscodingUrl", "{}")]
    public void UnsupportedOrMalformedNegotiationFailsClosed(string property, string value)
    {
        var source = Source(); source[property] = JsonNode.Parse(value);
        foreach (var force in new[] { false, true })
        foreach (var compatibility in new[] { false, true })
            Assert.Equal("playbackDiscImageUnsupported", Assert.Throws<InvalidOperationException>(() =>
                KaevoPlaybackProfilePolicy.SelectMode(Element(source), true, force, compatibility)).Message);
    }

    [Theory]
    [InlineData("mp4")]
    [InlineData("ts")]
    public void PathIdentifiedIsoUsesHlsEvenWithTransportStreamContainer(string outputContainer)
    {
        var source = Source(); source["Container"] = "ts"; source["Path"] = "/private/MOVIE.ISO";
        source["TranscodingContainer"] = outputContainer; source["SupportsDirectStream"] = false;
        Assert.Equal("transcode", KaevoPlaybackProfilePolicy.SelectMode(Element(source), true, false, true));
    }

    [Fact]
    public void OrdinaryMediaKeepsEveryExistingModeCombination()
    {
        foreach (var direct in new[] { false, true })
        foreach (var remux in new[] { false, true })
        foreach (var prefer in new[] { false, true })
        foreach (var force in new[] { false, true })
        foreach (var compatibility in new[] { false, true })
        {
            var source = JsonSerializer.SerializeToElement(new { Container = "mkv", Path = "/media/movie.mkv", SupportsDirectPlay = direct, SupportsDirectStream = remux });
            var expected = force ? "transcode" : compatibility || (prefer && direct) ? "direct_play" : direct || remux ? "remux" : "transcode";
            Assert.Equal(expected, KaevoPlaybackProfilePolicy.SelectMode(source, prefer, force, compatibility));
        }
    }

    private sealed class Provider(JsonObject source, bool denyItem) : HttpMessageHandler
    {
        internal int Calls;
        internal JsonElement Negotiation;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            Calls++;
            Assert.Equal("synthetic-jellyfin.invalid", request.RequestUri!.Host);
            Assert.Equal("MediaBrowser", request.Headers.Authorization?.Scheme);
            Assert.Contains("Token=\"synthetic-key\"", request.Headers.Authorization?.Parameter);
            Assert.False(request.Headers.Contains("X-Emby-Token"));
            object payload;
            if (request.RequestUri.AbsolutePath == $"/Items/{Item}/PlaybackInfo")
            {
                Assert.Equal(HttpMethod.Post, request.Method);
                Assert.Contains($"UserId={User}", request.RequestUri.Query);
                Negotiation = JsonSerializer.Deserialize<JsonElement>(await request.Content!.ReadAsStringAsync(token));
                Assert.Equal(User, Negotiation.GetProperty("userId").GetString());
                payload = new { MediaSources = new[] { source }, PlaySessionId = "play-session" };
            }
            else
            {
                Assert.Equal($"/Users/{User}/Items/{Item}", request.RequestUri.AbsolutePath);
                if (denyItem) return new HttpResponseMessage(HttpStatusCode.Forbidden) { Content = new StringContent("{}") };
                payload = new { Id = Item, Type = "Movie", RunTimeTicks = 60000000000L, MediaSources = new[] { Source() } };
            }
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json") };
        }
    }

    [Theory]
    [InlineData("hls")]
    [InlineData("unsupported")]
    [InlineData("wrong-profile")]
    [InlineData("item-denied")]
    [InlineData("missing-source-id")]
    [InlineData("audio-offset")]
    [InlineData("wrong-source-id")]
    public async Task RealPreparationPreservesScopeTracksAndBitrate(string scenario)
    {
        var source = Source();
        if (scenario == "unsupported") source["SupportsTranscoding"] = false;
        if (scenario == "missing-source-id") source.Remove("Id");
        if (scenario == "wrong-source-id") source["Id"] = "another-source";
        using var provider = new Provider(source, scenario == "item-denied");
        using var http = new HttpClient(provider);
        using var service = new KaevoCloudConnectorService(null!, null!, null!, null!, null!, null!, null!, null!,
            null!, null!, null!, null!, null!, NullLogger<KaevoCloudConnectorService>.Instance);
        var field = typeof(KaevoCloudConnectorService).GetField("_jellyfin", PrivateInstance)!;
        ((HttpClient)field.GetValue(service)!).Dispose(); field.SetValue(service, http);
        var config = new PluginConfiguration
        {
            LocalJellyfinBaseUrl = "http://synthetic-jellyfin.invalid", MaximumPlaybackBitrate = 24000000,
            ProfileJellyfinBindingsJson = JsonSerializer.Serialize(new Dictionary<string, string> { ["profile-current"] = User }),
            JellyfinPluginIntegrationsEnabled = false
        };
        var parameters = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>("""
            {"item_id":"0123456789abcdef0123456789abcdef","device_id":"ios-device",
             "max_bitrate":40000000,"audio_stream_index":1,"subtitle_stream_index":3,
             "compatibility_player":true,"prefer_direct_play":true}
            """)!;
        if (scenario == "audio-offset") parameters["audio_offset_ms"] = JsonSerializer.SerializeToElement(100);
        var request = new CloudRequest("request-id", "COMMAND", "jellyfin", "/commands/jellyfin.prepare_playback", null,
            "jellyfin.prepare_playback", parameters, scenario == "wrong-profile" ? "profile-other" : "profile-current");
        var method = typeof(KaevoCloudConnectorService).GetMethod("PreparePlaybackAsync", PrivateInstance)!;
        var task = (Task)method.Invoke(service, [config, new KaevoConnectorSecrets("", "", "synthetic-key"), request, parameters, CancellationToken.None])!;
        if (scenario != "hls")
        {
            var error = await Assert.ThrowsAsync<InvalidOperationException>(() => task);
            Assert.Equal(scenario switch
            {
                "wrong-profile" => "profileJellyfinBindingMissing", "item-denied" => "jellyfinHttp403",
                "missing-source-id" or "wrong-source-id" => "playbackIdentifiersMissing", _ => "playbackDiscImageUnsupported"
            }, error.Message);
            if (scenario == "wrong-profile") Assert.Equal(0, provider.Calls);
            return;
        }
        await task;
        var result = task.GetType().GetProperty("Result")!.GetValue(task)!;
        var payload = (JsonElement)result.GetType().GetProperty("Payload")!.GetValue(result)!;
        var descriptor = payload.GetProperty("result");
        Assert.Equal("remux", descriptor.GetProperty("mode").GetString());
        Assert.Equal(Item, descriptor.GetProperty("item_id").GetString());
        Assert.Equal("disc-source", descriptor.GetProperty("media_source_id").GetString());
        Assert.Equal("play-session", descriptor.GetProperty("playback_session_id").GetString());
        Assert.Equal(24000000, descriptor.GetProperty("max_bitrate").GetInt32());
        Assert.Equal(1, descriptor.GetProperty("selected_audio_stream_index").GetInt32());
        Assert.Equal(3, descriptor.GetProperty("selected_subtitle_stream_index").GetInt32());
        Assert.Equal(24000000, provider.Negotiation.GetProperty("maxStreamingBitrate").GetInt32());
        Assert.DoesNotContain("/private", payload.GetRawText());
        Assert.DoesNotContain("must-not-leak", payload.GetRawText());
        Assert.DoesNotContain("TranscodingUrl", payload.GetRawText());
    }
}
