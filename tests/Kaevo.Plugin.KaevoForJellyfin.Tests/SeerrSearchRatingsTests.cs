using System;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class SeerrSearchRatingsTests
{
    private static JsonElement Json(string value) => JsonSerializer.Deserialize<JsonElement>(value);
    [Fact]
    public async Task BatchesExactIdsCachesOnlyRatingsAndPreservesSearchMetadata()
    {
        var source = Json("""{"results":[{"id":1,"mediaType":"tv","name":"One","mediaInfo":{"status":5}},{"id":2,"mediaType":"movie","title":"Two"}]}""");
        var service = new KaevoSeerrSearchRatings();
        var calls = 0;
        Task<JsonElement> Read(string path, CancellationToken token)
        {
            Interlocked.Increment(ref calls);
            var id = int.Parse(path.Split('/').Last());
            return Task.FromResult(Json($$"""{"id":{{id}},"contentRatings":{"results":[{"iso_3166_1":"US","rating":"TV-PG"}]},"requests":[{"private":"must not be copied"}]}"""));
        }
        var result = await service.EnrichAsync(source, "server-one", Read, default);
        Assert.Equal(2, calls);
        var first = result.GetProperty("results")[0];
        Assert.Equal("One", first.GetProperty("name").GetString());
        Assert.Equal(5, first.GetProperty("mediaInfo").GetProperty("status").GetInt32());
        Assert.False(first.GetProperty("kaevoRatingDetails").TryGetProperty("requests", out _));
        await service.EnrichAsync(source, "server-one", Read, default);
        Assert.Equal(2, calls);
        await service.EnrichAsync(source, "server-two", Read, default);
        Assert.Equal(4, calls);
    }
    [Fact]
    public async Task FailureAndWrongIdentityStayUncheckedButRealUnratedIsRecorded()
    {
        var source = Json("""{"results":[{"id":1,"mediaType":"tv","name":"One"},{"id":2,"mediaType":"tv","name":"Two"},{"id":3,"mediaType":"tv","name":"Three"}]}""");
        var result = await new KaevoSeerrSearchRatings().EnrichAsync(source, "server", (path, token) =>
        {
            if (path.EndsWith("/1")) throw new InvalidOperationException();
            return Task.FromResult(Json(path.EndsWith("/2") ? "{\"id\":99}" : "{\"id\":3}"));
        }, default);
        var rows = result.GetProperty("results");
        Assert.False(rows[0].TryGetProperty("kaevoRatingDetails", out _));
        Assert.False(rows[1].TryGetProperty("kaevoRatingDetails", out _));
        Assert.Equal("{}", rows[2].GetProperty("kaevoRatingDetails").GetRawText());
    }
    [Fact]
    public async Task WorkIsBoundedAndCancellationCannotProduceACompletedResponse()
    {
        var source = JsonSerializer.SerializeToElement(new {results = Enumerable.Range(1, 30).Select(id => new {id, mediaType="tv", name="Title"})});
        int active=0, maximum=0, calls=0;
        var result = await new KaevoSeerrSearchRatings().EnrichAsync(source, "server", async (path, token) =>
        {
            Interlocked.Increment(ref calls);
            var current = Interlocked.Increment(ref active);
            maximum = Math.Max(maximum, current);
            try { await Task.Delay(10, token); return Json("{\"id\":" + path.Split('/').Last() + "}"); }
            finally { Interlocked.Decrement(ref active); }
        }, default);
        Assert.Equal(12, calls);
        Assert.InRange(maximum, 1, 4);
        Assert.Equal(30, result.GetProperty("results").GetArrayLength());
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new KaevoSeerrSearchRatings().EnrichAsync(source,"server", (_, token) => Task.FromCanceled<JsonElement>(token), cancelled.Token));
    }
    [Fact]
    public async Task MalformedMetadataCannotBreakSearchOrBeMarkedAsChecked()
    {
        var service = new KaevoSeerrSearchRatings();
        var notSearch = Json("[]");
        Assert.Equal("[]", (await service.EnrichAsync(notSearch, "scope", (_, _) => throw new Exception(), default)).GetRawText());
        var source = Json("""{"results":[{"id":1,"mediaType":"tv"},{"id":2,"mediaType":"movie"},{"id":"bad","mediaType":"tv"},{"id":3,"mediaType":7},null]}""");
        var result = await service.EnrichAsync(source, "scope", (path, _) => Task.FromResult(Json(
            path.EndsWith("/1") ? """{"id":1,"contentRatings":{"results":false}}""" :
            """{"id":2,"releases":{"results":[{"iso_3166_1":"US","rating":"R","private":"omit","release_dates":[{"certification":"R","private":"omit"}]}]}}""")), default);
        Assert.False(result.GetProperty("results")[0].TryGetProperty("kaevoRatingDetails", out _));
        var rating = result.GetProperty("results")[1].GetProperty("kaevoRatingDetails").GetRawText();
        Assert.Contains("certification", rating);
        Assert.DoesNotContain("private", rating);
        Assert.Equal(5, result.GetProperty("results").GetArrayLength());
    }

}
