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
    private static readonly HashSet<string> AllowedQueryKeys = new(StringComparer.Ordinal)
    {
        "mediaSourceId", "playSessionId", "deviceId", "static", "container", "segmentContainer",
        "segmentLength", "minSegments", "audioCodec", "videoCodec", "subtitleCodec", "audioBitRate",
        "videoBitRate", "maxWidth", "maxHeight", "audioStreamIndex", "subtitleStreamIndex",
        "enableAutoStreamCopy", "allowVideoStreamCopy", "allowAudioStreamCopy",
        "enableAdaptiveBitrateStreaming", "runtimeTicks", "actualSegmentLengthTicks"
    };

    public static PlaybackGrant VerifyGrant(string token, string grantKey, string connectorId)
    {
        if (grantKey.Length < 32)
        {
            throw new InvalidOperationException("playbackConnectorGrantKeyTooShort");
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
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
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

        return new PlaybackGrant(
            tokenConnectorId,
            RequiredString(payload, "device_id"),
            itemId,
            RequiredString(payload, "media_source_id"),
            RequiredString(payload, "playback_session_id"),
            mode,
            checked((int)RequiredInt64(payload, "max_bitrate")),
            expiresAt);
    }

    public static ResolvedPlaybackRequest Resolve(
        PlaybackGrant grant,
        string method,
        string path,
        IReadOnlyDictionary<string, JsonElement>? query,
        string? rangeHeader)
    {
        if (method is not ("GET" or "HEAD"))
        {
            throw new InvalidOperationException("playbackMethodNotAllowed");
        }

        var staticMatch = StaticRouteRegex().Match(path);
        var segmentMatch = SegmentRouteRegex().Match(path);
        var match = staticMatch.Success ? staticMatch : segmentMatch;
        if (!match.Success || !string.Equals(match.Groups[1].Value, grant.ItemId, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("playbackRouteNotAllowed");
        }

        var route = staticMatch.Success ? staticMatch.Groups[2].Value : "segment";
        if ((grant.Mode == "direct_play" && route != "stream")
            || (grant.Mode != "direct_play" && route == "stream"))
        {
            throw new InvalidOperationException("playbackModeRouteMismatch");
        }

        var normalized = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var pair in query ?? new Dictionary<string, JsonElement>())
        {
            if (!AllowedQueryKeys.Contains(pair.Key))
            {
                throw new InvalidOperationException("playbackQueryNotAllowed");
            }

            normalized[pair.Key] = pair.Value.ValueKind == JsonValueKind.String
                ? pair.Value.GetString() ?? string.Empty
                : pair.Value.ToString();
        }

        Bind(normalized, "mediaSourceId", grant.MediaSourceId);
        Bind(normalized, "playSessionId", grant.PlaybackSessionId);
        Bind(normalized, "deviceId", grant.DeviceId);

        var bitrate = ParseNonNegative(normalized, "audioBitRate") + ParseNonNegative(normalized, "videoBitRate");
        if (bitrate > grant.MaximumBitrate)
        {
            throw new InvalidOperationException("playbackBitrateExceeded");
        }

        if (!string.IsNullOrWhiteSpace(rangeHeader)
            && (grant.Mode != "direct_play" || !RangeRegex().IsMatch(rangeHeader)))
        {
            throw new InvalidOperationException("playbackRangeInvalid");
        }

        var encodedQuery = string.Join('&', normalized.Select(pair =>
            $"{Uri.EscapeDataString(pair.Key)}={Uri.EscapeDataString(pair.Value)}"));
        return new ResolvedPlaybackRequest(
            method == "HEAD" ? HttpMethod.Head : HttpMethod.Get,
            encodedQuery.Length == 0 ? path : $"{path}?{encodedQuery}",
            rangeHeader);
    }

    private static void Bind(IDictionary<string, string> values, string key, string expected)
    {
        if (values.TryGetValue(key, out var supplied) && !string.Equals(supplied, expected, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("playbackSessionBindingMismatch");
        }

        values[key] = expected;
    }

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

    [GeneratedRegex("^/Videos/([0-9a-fA-F]{32})/(stream|master\\.m3u8|main\\.m3u8)$", RegexOptions.CultureInvariant)]
    private static partial Regex StaticRouteRegex();

    [GeneratedRegex("^/Videos/([0-9a-fA-F]{32})/hls1/main/(\\d+)\\.(ts|mp4|m4s)$", RegexOptions.CultureInvariant)]
    private static partial Regex SegmentRouteRegex();

    [GeneratedRegex("^bytes=\\d*-\\d*$", RegexOptions.CultureInvariant)]
    private static partial Regex RangeRegex();
}
