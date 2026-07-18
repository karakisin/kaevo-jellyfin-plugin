using System.Text.RegularExpressions;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

internal static partial class KaevoPlaybackPlaylistRewriter
{
    public static string Rewrite(
        string playlist,
        string grantToken,
        string itemId,
        string mediaSourceId,
        string sourcePath)
    {
        if (string.IsNullOrWhiteSpace(grantToken)
            || string.IsNullOrWhiteSpace(itemId)
            || !sourcePath.StartsWith("/Videos/", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("playlistContextInvalid");
        }

        var sourcePathOnly = sourcePath.Split('?', 2)[0];
        var baseUri = new Uri(new Uri("https://kaevo.invalid"), sourcePathOnly);
        var relayPrefix = $"/v1/playback/{Uri.EscapeDataString(grantToken)}";
        var hasTrailingNewline = playlist.EndsWith('\n');
        var normalized = playlist.Replace("\r\n", "\n", StringComparison.Ordinal);
        var lines = normalized.Split('\n');

        for (var index = 0; index < lines.Length; index++)
        {
            var line = lines[index];
            if (line.Length == 0)
            {
                continue;
            }

            if (line.StartsWith('#'))
            {
                lines[index] = UriAttributeRegex().Replace(line, match =>
                {
                    var rewritten = RewriteUri(match.Groups[1].Value, baseUri, relayPrefix, itemId, mediaSourceId);
                    return $"URI=\"{rewritten}\"";
                });
                continue;
            }

            var leadingLength = line.Length - line.TrimStart().Length;
            var trailingLength = line.Length - line.TrimEnd().Length;
            var leading = leadingLength == 0 ? string.Empty : line[..leadingLength];
            var trailing = trailingLength == 0 ? string.Empty : line[^trailingLength..];
            lines[index] = leading + RewriteUri(line.Trim(), baseUri, relayPrefix, itemId, mediaSourceId) + trailing;
        }

        var rewrittenPlaylist = string.Join('\n', lines);
        if (hasTrailingNewline && !rewrittenPlaylist.EndsWith('\n'))
        {
            rewrittenPlaylist += "\n";
        }
        return rewrittenPlaylist;
    }

    private static string RewriteUri(string value, Uri baseUri, string relayPrefix, string itemId, string mediaSourceId)
    {
        if (string.IsNullOrWhiteSpace(value)
            || value.StartsWith("//", StringComparison.Ordinal)
            || (!value.StartsWith('/') && Uri.TryCreate(value, UriKind.Absolute, out _)))
        {
            throw new InvalidOperationException("playlistUriNotAllowed");
        }

        if (!Uri.TryCreate(baseUri, value, out var resolved))
        {
            throw new InvalidOperationException("playlistUriInvalid");
        }

        var path = Uri.UnescapeDataString(resolved.AbsolutePath);
        if (!KaevoPlaybackSecurity.IsHlsSessionResourcePath(path, itemId, mediaSourceId))
        {
            throw new InvalidOperationException("playlistUriNotAllowed");
        }

        var safeQuery = resolved.Query
            .TrimStart('?')
            .Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Where(pair => !IsAuthenticationQuery(pair))
            .ToArray();
        var querySuffix = safeQuery.Length == 0 ? string.Empty : $"?{string.Join('&', safeQuery)}";

        // Jellyfin normally emits child playlists and segments relative to the
        // current manifest. Preserve that safe relative form after validation
        // and credential stripping. AVPlayer will resolve it beneath the same
        // signed relay URL, avoiding thousands of repeated grant tokens in a
        // long VOD playlist. Root-relative Jellyfin URIs still need an explicit
        // relay prefix so they cannot escape the signed playback route.
        if (!value.StartsWith('/'))
        {
            var relativePath = value.Split('?', 2)[0];
            return relativePath + querySuffix;
        }

        return relayPrefix + resolved.AbsolutePath + querySuffix;
    }

    private static bool IsAuthenticationQuery(string pair)
    {
        var separator = pair.IndexOf('=');
        var encodedKey = separator < 0 ? pair : pair[..separator];
        var key = Uri.UnescapeDataString(encodedKey);
        return key.Equals("api_key", StringComparison.OrdinalIgnoreCase)
            || key.Equals("apikey", StringComparison.OrdinalIgnoreCase)
            || key.Equals("access_token", StringComparison.OrdinalIgnoreCase)
            || key.Equals("token", StringComparison.OrdinalIgnoreCase);
    }

    [GeneratedRegex("URI=\"([^\"]+)\"", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UriAttributeRegex();
}
