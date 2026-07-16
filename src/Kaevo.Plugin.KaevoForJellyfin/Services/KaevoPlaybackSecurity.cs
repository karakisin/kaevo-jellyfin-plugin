using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

internal sealed record PlaybackGrant(
    string ConnectorId,
    string DeviceId,
    string ItemId,
    string MediaSourceId,
    string PlaybackSessionId,
    string Mode,
    int MaximumBitrate,
    long ExpiresAt);

internal sealed record ResolvedPlaybackRequest(
    HttpMethod Method,
    string PathAndQuery,
    string? RangeHeader);

internal static partial class KaevoPlaybackSecurity
{
    private const long MaximumActivePlaybackSeconds = 12 * 60 * 60;
    private const long MaximumIdlePlaybackSeconds = 5 * 60;
    private const int MaximumActivePlaybackGrants = 256;
    private const int MaximumQueryParameters = 96;
    private const int MaximumQueryValueLength = 4096;
    private const int MaximumEncodedQueryLength = 32 * 1024;
    private sealed record ActivePlaybackGrant(PlaybackGrant Grant, long ActivatedAt, long LastSeenAt);
    private static readonly ConcurrentDictionary<string, ActivePlaybackGrant> ActiveGrants = new(StringComparer.Ordinal);

    private static readonly HashSet<string> BlockedQueryKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "api_key", "apikey", "access_token", "token", "authorization",
        "x-emby-token", "x-mediabrowser-token", "x-emby-authorization"
    };

    private enum PlaybackResourceKind
    {
        DirectStream,
        Playlist,
        Segment
    }

    public static PlaybackGrant VerifyGrant(string token, string grantKey, string connectorId, long? nowEpoch = null)
    {
        if (grantKey.Length < 32)
        {
            throw new InvalidOperationException("playbackConnectorGrantKeyTooShort");
        }

        var now = nowEpoch ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var tokenHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));
        if (ActiveGrants.TryGetValue(tokenHash, out var active))
        {
            if (!string.Equals(active.Grant.ConnectorId, connectorId, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("playbackGrantConnectorMismatch");
            }
            if (now - active.ActivatedAt <= MaximumActivePlaybackSeconds
                && now - active.LastSeenAt <= MaximumIdlePlaybackSeconds)
            {
                ActiveGrants[tokenHash] = active with { LastSeenAt = now };
                return active.Grant;
            }
            ActiveGrants.TryRemove(tokenHash, out _);
        }

        var encodedPayload = token.Split('.', 2)[0];
        var json = Encoding.UTF8.GetString(Base64UrlDecode(encodedPayload));
        var payload = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json)
            ?? throw new InvalidOperationException("playbackGrantMalformed");
        if (!payload.Remove("home_sig", out var signatureElement))
        {
            throw new InvalidOperationException("playbackGrantSignatureInvalid");
        }

        var canonical = JsonSerializer.Serialize(new SortedDictionary<string, JsonElement>(payload, StringComparer.Ordinal));
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(grantKey));
        var expected = hmac.ComputeHash(Encoding.UTF8.GetBytes(canonical));
        var supplied = Base64UrlDecode(signatureElement.GetString() ?? string.Empty);
        if (!CryptographicOperations.FixedTimeEquals(expected, supplied))
        {
            throw new InvalidOperationException("playbackGrantSignatureInvalid");
        }

        var expiresAt = RequiredInt64(payload, "exp");
        var notBefore = RequiredInt64(payload, "nbf");
        if (now < notBefore || now >= expiresAt)
        {
            throw new InvalidOperationException("playbackGrantExpired");
        }

        var tokenConnectorId = RequiredString(payload, "connector_id");
        if (!string.Equals(tokenConnectorId, connectorId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("playbackGrantConnectorMismatch");
        }

        var itemId = RequiredString(payload, "item_id").ToLowerInvariant();
        if (!ItemIdRegex().IsMatch(itemId))
        {
            throw new InvalidOperationException("playbackGrantItemInvalid");
        }

        var mode = RequiredString(payload, "mode");
        if (mode is not ("direct_play" or "remux" or "transcode"))
        {
            throw new InvalidOperationException("playbackGrantModeInvalid");
        }

        var grant = new PlaybackGrant(
            tokenConnectorId,
            RequiredString(payload, "device_id"),
            itemId,
            RequiredString(payload, "media_source_id"),
            RequiredString(payload, "playback_session_id"),
            mode,
            checked((int)RequiredInt64(payload, "max_bitrate")),
            expiresAt);
        if (grant.MaximumBitrate is < 1 or > 100_000_000)
        {
            throw new InvalidOperationException("playbackGrantBitrateInvalid");
        }
        ActiveGrants[tokenHash] = new ActivePlaybackGrant(grant, now, now);
        TrimActiveGrants(now);
        return grant;
    }

    internal static void ResetActiveGrantsForTests() => ActiveGrants.Clear();

    private static void TrimActiveGrants(long now)
    {
        foreach (var pair in ActiveGrants)
        {
            if (now - pair.Value.ActivatedAt > MaximumActivePlaybackSeconds
                || now - pair.Value.LastSeenAt > MaximumIdlePlaybackSeconds)
            {
                ActiveGrants.TryRemove(pair.Key, out _);
            }
        }
        if (ActiveGrants.Count <= MaximumActivePlaybackGrants)
        {
            return;
        }
        foreach (var key in ActiveGrants
            .OrderBy(pair => pair.Value.LastSeenAt)
            .Take(ActiveGrants.Count - MaximumActivePlaybackGrants)
            .Select(pair => pair.Key))
        {
            ActiveGrants.TryRemove(key, out _);
        }
    }

    public static ResolvedPlaybackRequest Resolve(
        PlaybackGrant grant,
        string method,
        string path,
        IReadOnlyDictionary<string, JsonElement>? query,
        string? rangeHeader)
    {
        if (!string.Equals(method, "GET", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(method, "HEAD", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("playbackMethodNotAllowed");
        }

        var resource = ResolveResource(path, grant.ItemId);
        if ((grant.Mode == "direct_play" && resource != PlaybackResourceKind.DirectStream)
            || (grant.Mode != "direct_play" && resource == PlaybackResourceKind.DirectStream))
        {
            throw new InvalidOperationException("playbackModeRouteMismatch");
        }

        if (query?.Count > MaximumQueryParameters)
        {
            throw new InvalidOperationException("playbackQueryTooLarge");
        }

        var normalized = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var pair in query ?? new Dictionary<string, JsonElement>(StringComparer.OrdinalIgnoreCase))
        {
            if (!QueryKeyRegex().IsMatch(pair.Key) || BlockedQueryKeys.Contains(pair.Key))
            {
                throw new InvalidOperationException("playbackQueryNotAllowed");
            }

            if (normalized.ContainsKey(pair.Key))
            {
                throw new InvalidOperationException("playbackQueryDuplicate");
            }

            var value = ScalarQueryValue(pair.Value);
            if (value.Length > MaximumQueryValueLength
                || value.IndexOfAny(['\r', '\n', '\0']) >= 0)
            {
                throw new InvalidOperationException("playbackQueryInvalid");
            }

            normalized.Add(pair.Key, value);
        }

        Bind(normalized, "mediaSourceId", grant.MediaSourceId);
        Bind(normalized, "playSessionId", grant.PlaybackSessionId);
        Bind(normalized, "deviceId", grant.DeviceId);

        var audioBitrate = ParseNonNegative(normalized, "audioBitRate");
        var videoBitrate = ParseNonNegative(normalized, "videoBitRate");
        var maximumStreamingBitrate = ParseNonNegative(normalized, "maxStreamingBitrate");
        if (audioBitrate > grant.MaximumBitrate
            || videoBitrate > grant.MaximumBitrate
            || maximumStreamingBitrate > grant.MaximumBitrate
            || audioBitrate > grant.MaximumBitrate - videoBitrate)
        {
            throw new InvalidOperationException("playbackBitrateExceeded");
        }

        if (!string.IsNullOrWhiteSpace(rangeHeader)
            && !RangeRegex().IsMatch(rangeHeader))
        {
            throw new InvalidOperationException("playbackRangeInvalid");
        }

        var encodedQuery = string.Join('&', normalized.Select(pair =>
            $"{Uri.EscapeDataString(pair.Key)}={Uri.EscapeDataString(pair.Value)}"));
        if (encodedQuery.Length > MaximumEncodedQueryLength)
        {
            throw new InvalidOperationException("playbackQueryTooLarge");
        }
        return new ResolvedPlaybackRequest(
            string.Equals(method, "HEAD", StringComparison.OrdinalIgnoreCase) ? HttpMethod.Head : HttpMethod.Get,
            encodedQuery.Length == 0 ? path : $"{path}?{encodedQuery}",
            rangeHeader);
    }

    private static void Bind(IDictionary<string, string> values, string key, string expected)
    {
        if (values.TryGetValue(key, out var supplied) && !string.Equals(supplied, expected, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("playbackSessionBindingMismatch");
        }

        values.Remove(key);
        values[key] = expected;
    }

    internal static bool IsHlsSessionResourcePath(string path, string itemId)
    {
        try
        {
            return ResolveResource(path, itemId) is PlaybackResourceKind.Playlist or PlaybackResourceKind.Segment;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }

    private static PlaybackResourceKind ResolveResource(string path, string itemId)
    {
        if (string.IsNullOrWhiteSpace(path)
            || path.Length > 2048
            || path.Contains('\\')
            || path.Contains('?')
            || path.Contains('#')
            || path.Contains("//", StringComparison.Ordinal))
        {
            throw new InvalidOperationException("playbackRouteNotAllowed");
        }

        var segments = path.Split('/', StringSplitOptions.None);
        if (segments.Length < 4
            || segments[0].Length != 0
            || !string.Equals(segments[1], "Videos", StringComparison.OrdinalIgnoreCase)
            || !ItemIdPathRegex().IsMatch(segments[2])
            || !string.Equals(NormalizeItemId(segments[2]), NormalizeItemId(itemId), StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("playbackRouteNotAllowed");
        }

        var resourceSegments = segments[3..];
        if (resourceSegments.Any(segment => string.IsNullOrWhiteSpace(segment)
            || segment is "." or ".."
            || !SafePathSegmentRegex().IsMatch(segment)))
        {
            throw new InvalidOperationException("playbackRouteNotAllowed");
        }

        if (resourceSegments.Length == 1 && DirectStreamRegex().IsMatch(resourceSegments[0]))
        {
            return PlaybackResourceKind.DirectStream;
        }

        if (resourceSegments.Length == 1 && PlaylistFileRegex().IsMatch(resourceSegments[0]))
        {
            return PlaybackResourceKind.Playlist;
        }

        if (resourceSegments.Length is < 2 or > 7 || !HlsPlaylistIdRegex().IsMatch(resourceSegments[0]))
        {
            throw new InvalidOperationException("playbackRouteNotAllowed");
        }

        var final = resourceSegments[^1];
        if (PlaylistFileRegex().IsMatch(final))
        {
            return PlaybackResourceKind.Playlist;
        }

        if (SegmentFileRegex().IsMatch(final))
        {
            return PlaybackResourceKind.Segment;
        }

        throw new InvalidOperationException("playbackRouteNotAllowed");
    }

    private static string NormalizeItemId(string value) => value.Replace("-", string.Empty, StringComparison.Ordinal);

    private static string ScalarQueryValue(JsonElement value)
        => value.ValueKind switch
        {
            JsonValueKind.String => value.GetString() ?? string.Empty,
            JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False or JsonValueKind.Null => value.ToString(),
            _ => throw new InvalidOperationException("playbackQueryInvalid")
        };

    private static long ParseNonNegative(IReadOnlyDictionary<string, string> values, string key)
    {
        if (!values.TryGetValue(key, out var supplied))
        {
            return 0;
        }

        if (!long.TryParse(supplied, out var value) || value < 0)
        {
            throw new InvalidOperationException("playbackBitrateInvalid");
        }

        return value;
    }

    private static string RequiredString(IReadOnlyDictionary<string, JsonElement> payload, string key)
        => payload.TryGetValue(key, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString() ?? throw new InvalidOperationException("playbackGrantMalformed")
            : throw new InvalidOperationException("playbackGrantMalformed");

    private static long RequiredInt64(IReadOnlyDictionary<string, JsonElement> payload, string key)
        => payload.TryGetValue(key, out var value) && value.TryGetInt64(out var parsed)
            ? parsed
            : throw new InvalidOperationException("playbackGrantMalformed");

    private static byte[] Base64UrlDecode(string value)
    {
        var padded = value.Replace('-', '+').Replace('_', '/');
        padded += new string('=', (4 - (padded.Length % 4)) % 4);
        return Convert.FromBase64String(padded);
    }

    [GeneratedRegex("^[0-9a-f]{32}$", RegexOptions.CultureInvariant)]
    private static partial Regex ItemIdRegex();

    [GeneratedRegex("^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})$", RegexOptions.CultureInvariant)]
    private static partial Regex ItemIdPathRegex();

    [GeneratedRegex("^[A-Za-z][A-Za-z0-9_.\\[\\]-]{0,95}$", RegexOptions.CultureInvariant)]
    private static partial Regex QueryKeyRegex();

    [GeneratedRegex("^[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}$", RegexOptions.CultureInvariant)]
    private static partial Regex SafePathSegmentRegex();

    [GeneratedRegex("^stream(?:\\.(?:mp4|m4v|mov|mkv|webm|ts))?$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex DirectStreamRegex();

    // Jellyfin can name alternate audio/subtitle rendition playlists with
    // stream indexes (for example audio/0.m3u8). The surrounding route checks
    // still bind every resource to the granted item and hlsN session tree.
    [GeneratedRegex("^[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}\\.m3u8$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex PlaylistFileRegex();

    [GeneratedRegex("^hls[0-9]{1,3}$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex HlsPlaylistIdRegex();

    [GeneratedRegex("^[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}\\.(?:ts|mp4|m4s|aac|m4a|mp3|vtt|webvtt)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex SegmentFileRegex();

    [GeneratedRegex("^bytes=(?:[0-9]+-[0-9]*|-[0-9]+)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RangeRegex();
}
