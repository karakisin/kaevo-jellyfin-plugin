using System.Text.Json;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class SeerrRequestRemovalTests
{
    private static Dictionary<string, JsonElement> Parameters() => JsonSerializer.SerializeToElement(new
        { connector_id = "connector-test", request_id = 17, media_id = 24, media_type = "movie", is_4k = false })
        .EnumerateObject().ToDictionary(p => p.Name, p => p.Value.Clone());
    private static JsonElement Record(int id = 17, int mediaId = 24, string type = "movie", bool is4k = false) =>
        JsonSerializer.SerializeToElement(new { id, type, is4k, media = new { id = 99, tmdbId = mediaId } });

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ExactRecordRemovedOnceAndAbsenceReadBack(bool alreadyAbsent)
    {
        var calls = new List<string>();
        Task<JsonElement> Send(HttpMethod method, string path, CancellationToken token)
        {
            Assert.Equal("/api/v1/request/17", path);
            calls.Add(method.Method);
            if (alreadyAbsent || calls.Count == 3) throw new InvalidOperationException("seerrHttp404");
            return Task.FromResult(method == HttpMethod.Get ? Record() : JsonSerializer.SerializeToElement(new { ok = true }));
        }
        var receipt = JsonSerializer.SerializeToElement(await SeerrRequestRemoval.ExecuteAsync(Parameters(), "connector-test", Send, default));
        Assert.Equal(alreadyAbsent ? new[] { "GET" } : new[] { "GET", "DELETE", "GET" }, calls);
        Assert.True(receipt.GetProperty("verified_absent").GetBoolean());
        Assert.Equal(24, receipt.GetProperty("media_id").GetInt32());
        Assert.Equal(alreadyAbsent, receipt.GetProperty("already_absent").GetBoolean());
    }

    [Theory]
    [InlineData(18, 24, "movie", false)]
    [InlineData(17, 25, "movie", false)]
    [InlineData(17, 24, "tv", false)]
    [InlineData(17, 24, "movie", true)]
    public async Task ChangedIdentityNeverDeletes(int id, int mediaId, string type, bool quality)
    {
        var calls = 0;
        await Assert.ThrowsAsync<InvalidOperationException>(() => SeerrRequestRemoval.ExecuteAsync(Parameters(), "connector-test",
            (method, path, token) => { calls++; Assert.Equal(HttpMethod.Get, method); return Task.FromResult(Record(id, mediaId, type, quality)); }, default));
        Assert.Equal(1, calls);
    }

    [Theory]
    [InlineData("seerrHttp401")]
    [InlineData("seerrHttp403")]
    [InlineData("seerrHttp500")]
    public async Task FailedReadNeverMeansAbsent(string error)
    {
        var calls = 0;
        await Assert.ThrowsAsync<InvalidOperationException>(() => SeerrRequestRemoval.ExecuteAsync(Parameters(), "connector-test",
            (method, path, token) => { calls++; Assert.Equal(HttpMethod.Get, method); throw new InvalidOperationException(error); }, default));
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task UncertainDeleteIsNotRepeatedOrReportedSuccessful()
    {
        var calls = new List<string>();
        await Assert.ThrowsAsync<TaskCanceledException>(() => SeerrRequestRemoval.ExecuteAsync(Parameters(), "connector-test",
            (method, path, token) => { calls.Add(method.Method); if (method == HttpMethod.Delete) throw new TaskCanceledException(); return Task.FromResult(Record()); }, default));
        Assert.Equal(new[] { "GET", "DELETE" }, calls);
    }

    [Fact]
    public async Task StillPresentAfterDeleteFailsVerification()
    {
        var calls = new List<string>();
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => SeerrRequestRemoval.ExecuteAsync(Parameters(), "connector-test",
            (method, path, token) => { calls.Add(method.Method); return Task.FromResult(Record()); }, default));
        Assert.Equal("seerrRemovalNotConfirmed", error.Message);
        Assert.Equal(new[] { "GET", "DELETE", "GET" }, calls);
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("null")]
    [InlineData("{\"id\":17,\"type\":\"movie\",\"media\":{\"tmdbId\":24}}")]
    public async Task IncompleteProviderRecordNeverDeletes(string json)
    {
        await Assert.ThrowsAsync<InvalidOperationException>(() => SeerrRequestRemoval.ExecuteAsync(Parameters(), "connector-test",
            (method, path, token) => { Assert.Equal(HttpMethod.Get, method); return Task.FromResult(JsonDocument.Parse(json).RootElement.Clone()); }, default));
    }

    [Theory]
    [InlineData("request_id", "true")]
    [InlineData("request_id", "0")]
    [InlineData("media_id", "-1")]
    [InlineData("is_4k", "\"false\"")]
    [InlineData("media_type", "\"music\"")]
    [InlineData("delete_files", "true")]
    [InlineData("connector_id", "\"other-connector\"")]
    public async Task InvalidParametersNeverContactProvider(string key, string value)
    {
        var parameters = Parameters(); parameters[key] = JsonDocument.Parse(value).RootElement.Clone();
        await Assert.ThrowsAsync<InvalidOperationException>(() => SeerrRequestRemoval.ExecuteAsync(parameters, "connector-test",
            (method, path, token) => throw new Xunit.Sdk.XunitException("Must not contact provider"), default));
    }
}
