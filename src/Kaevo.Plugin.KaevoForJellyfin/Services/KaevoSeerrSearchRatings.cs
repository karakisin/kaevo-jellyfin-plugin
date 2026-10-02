using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

/// Carries public rating metadata with a search response, not personal request
/// data. The app still makes the parental decision for every selected viewer.
internal sealed class KaevoSeerrSearchRatings
{
    private readonly ConcurrentDictionary<string, (DateTimeOffset Date, JsonElement Value)> _cache = new();
    private readonly SemaphoreSlim _reads = new(4);

    internal async Task<JsonElement> EnrichAsync(
        JsonElement response, string scope,
        Func<string, CancellationToken, Task<JsonElement>> read,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (response.ValueKind != JsonValueKind.Object || !response.TryGetProperty("results", out var results) || results.ValueKind != JsonValueKind.Array)
            return response;
        var candidates = results.EnumerateArray().Where(item =>
            item.ValueKind == JsonValueKind.Object
            && item.TryGetProperty("id", out var id) && id.ValueKind == JsonValueKind.Number && id.TryGetInt32(out var number) && number > 0
            && item.TryGetProperty("mediaType", out var type) && type.ValueKind == JsonValueKind.String && type.GetString() is "movie" or "tv"
            && !(item.TryGetProperty("adult", out var adult) && adult.ValueKind == JsonValueKind.True))
            .Take(12).ToArray();
        if (candidates.Length == 0) return response;
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        budget.CancelAfter(TimeSpan.FromSeconds(2));
        var ratings = new ConcurrentDictionary<string, JsonElement>();
        await Task.WhenAll(candidates.Select(async item =>
        {
            var id = item.GetProperty("id").GetInt32();
            var type = item.GetProperty("mediaType").GetString()!;
            var path = $"/api/v1/{type}/{id}";
            var key = scope + "|" + path;
            if (_cache.TryGetValue(key, out var cached) && DateTimeOffset.UtcNow - cached.Date < TimeSpan.FromHours(1))
            {
                ratings[path] = cached.Value;
                return;
            }
            var acquired = false;
            try
            {
                await _reads.WaitAsync(budget.Token).ConfigureAwait(false);
                acquired = true;
                var details = await read(path, budget.Token).ConfigureAwait(false);
                // Never attach metadata belonging to a different canonical item.
                if (details.ValueKind != JsonValueKind.Object || !details.TryGetProperty("id", out var actual)
                    || actual.ValueKind != JsonValueKind.Number || !actual.TryGetInt32(out var actualID) || actualID != id)
                    return;
                var projection = new JsonObject();
                foreach (var field in new[] { "contentRatings", "releases" })
                {
                    if (details.TryGetProperty(field, out var value) && value.ValueKind != JsonValueKind.Null)
                        projection[field] = RatingCollection(value, field == "releases");
                }
                // An empty object means the lookup succeeded but no rating exists.
                var encoded = projection.ToJsonString();
                if (encoded.Length > 32_768) return;
                var rating = JsonSerializer.Deserialize<JsonElement>(encoded);
                ratings[path] = rating;
                if (_cache.Count >= 512) _cache.Clear();
                _cache[key] = (DateTimeOffset.UtcNow, rating);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { }
            catch (Exception) when (!cancellationToken.IsCancellationRequested)
            {
                // Failed checks stay absent so the app's existing exact-item
                // fallback can retry. Never mark a failure as "unrated".
            }
            finally { if (acquired) _reads.Release(); }
        })).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (ratings.IsEmpty) return response;
        var output = JsonNode.Parse(response.GetRawText())!.AsObject();
        foreach (var node in output["results"]!.AsArray())
        {
            if (node is not JsonObject item || item["id"] is not JsonValue id || item["mediaType"] is not JsonValue type
                || !id.TryGetValue<int>(out var number) || !type.TryGetValue<string>(out var mediaType)) continue;
            var path = $"/api/v1/{mediaType}/{number}";
            if (ratings.TryGetValue(path, out var rating)) item["kaevoRatingDetails"] = JsonNode.Parse(rating.GetRawText());
        }
        return JsonSerializer.Deserialize<JsonElement>(output.ToJsonString());
    }

    private static JsonObject RatingCollection(JsonElement value, bool movie)
    {
        if (value.ValueKind != JsonValueKind.Object || !value.TryGetProperty("results", out var rows)
            || rows.ValueKind != JsonValueKind.Array || rows.GetArrayLength() > 256)
            throw new FormatException("Invalid rating collection");
        var output = new JsonArray();
        foreach (var row in rows.EnumerateArray())
        {
            if (row.ValueKind != JsonValueKind.Object || !row.TryGetProperty("iso_3166_1", out var country)
                || country.ValueKind != JsonValueKind.String || country.GetString()!.Length > 8)
                throw new FormatException("Invalid rating country");
            var item = new JsonObject { ["iso_3166_1"] = country.GetString() };
            item["rating"] = OptionalText(row, "rating");
            if (movie)
            {
                var dates = new JsonArray();
                if (row.TryGetProperty("release_dates", out var source) && source.ValueKind != JsonValueKind.Null)
                {
                    if (source.ValueKind != JsonValueKind.Array || source.GetArrayLength() > 256)
                        throw new FormatException("Invalid release ratings");
                    foreach (var date in source.EnumerateArray())
                        dates.Add(new JsonObject { ["certification"] = OptionalText(date, "certification") });
                }
                item["release_dates"] = dates;
            }
            output.Add(item);
        }
        return new JsonObject { ["results"] = output };
    }

    private static string? OptionalText(JsonElement row, string name)
    {
        if (row.ValueKind != JsonValueKind.Object) throw new FormatException("Invalid rating entry");
        if (!row.TryGetProperty(name, out var value) || value.ValueKind == JsonValueKind.Null) return null;
        if (value.ValueKind != JsonValueKind.String || value.GetString()!.Length > 128)
            throw new FormatException("Invalid rating text");
        return value.GetString();
    }

}
