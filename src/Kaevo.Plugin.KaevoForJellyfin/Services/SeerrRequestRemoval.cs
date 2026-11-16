using System.Text.Json;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

/// <summary>Removes only an exact Seerr request. Never touches Arr, jobs or files.</summary>
internal static class SeerrRequestRemoval
{
    internal static async Task<object> ExecuteAsync(
        IReadOnlyDictionary<string, JsonElement> parameters, string connectorId,
        Func<HttpMethod, string, CancellationToken, Task<JsonElement>> send,
        CancellationToken cancellationToken)
    {
        if (parameters.Count != 5
            || !parameters.TryGetValue("connector_id", out var connector)
            || connector.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(connectorId) || connector.GetString() != connectorId
            || !Positive(parameters, "request_id", out var requestId)
            || !Positive(parameters, "media_id", out var mediaId)
            || !parameters.TryGetValue("media_type", out var type)
            || type.ValueKind != JsonValueKind.String
            || type.GetString() is not ("movie" or "tv")
            || !parameters.TryGetValue("is_4k", out var quality)
            || quality.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
            throw new InvalidOperationException("seerrRemovalParametersInvalid");

        var mediaType = type.GetString()!;
        var is4K = quality.GetBoolean();
        var path = $"/api/v1/request/{requestId}";
        JsonElement? existing = await ReadAsync(send, path, cancellationToken).ConfigureAwait(false);
        var alreadyAbsent = existing is null;
        if (existing is { } record)
        {
            if (record.ValueKind != JsonValueKind.Object
                || !record.TryGetProperty("id", out var id) || !id.TryGetInt32(out var foundId) || foundId != requestId
                || !record.TryGetProperty("type", out var foundType) || foundType.ValueKind != JsonValueKind.String || foundType.GetString() != mediaType
                || !record.TryGetProperty("is4k", out var foundQuality) || foundQuality.ValueKind is not (JsonValueKind.True or JsonValueKind.False) || foundQuality.GetBoolean() != is4K
                || !record.TryGetProperty("media", out var media) || media.ValueKind != JsonValueKind.Object
                || !media.TryGetProperty("tmdbId", out var tmdb) || !tmdb.TryGetInt32(out var foundMediaId) || foundMediaId != mediaId)
                throw new InvalidOperationException("seerrRemovalIdentityMismatch");

            // Exactly one DELETE. A failed/unknown response is never retried here.
            await send(HttpMethod.Delete, path, cancellationToken).ConfigureAwait(false);
            if (await ReadAsync(send, path, cancellationToken).ConfigureAwait(false) is not null)
                throw new InvalidOperationException("seerrRemovalNotConfirmed");
        }
        return new { request_id = requestId, media_id = mediaId, media_type = mediaType,
            is_4k = is4K, removed = true, verified_absent = true, already_absent = alreadyAbsent };
    }

    private static bool Positive(IReadOnlyDictionary<string, JsonElement> parameters, string key, out int value)
    {
        value = 0;
        return parameters.TryGetValue(key, out var element) && element.ValueKind == JsonValueKind.Number
            && element.TryGetInt32(out value) && value > 0;
    }

    private static async Task<JsonElement?> ReadAsync(
        Func<HttpMethod, string, CancellationToken, Task<JsonElement>> send, string path, CancellationToken cancellationToken)
    {
        try { return await send(HttpMethod.Get, path, cancellationToken).ConfigureAwait(false); }
        catch (InvalidOperationException error) when (error.Message == "seerrHttp404") { return null; }
    }
}
