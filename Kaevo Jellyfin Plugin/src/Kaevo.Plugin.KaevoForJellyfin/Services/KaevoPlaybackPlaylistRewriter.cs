using System.Text.RegularExpressions;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

internal static partial class KaevoPlaybackPlaylistRewriter
{
    public static string Rewrite(
        string playlist,
        string grantToken,
        string itemId,
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
                    var rewritten = RewriteUri(match.Groups[1].Value, baseUri, relayPrefix, itemId);
                    return $"URI=\"{rewritten}\"";
                });
                continue;
            }

            var leadingLength = line.Length - line.TrimStart().Length;
            var trailingLength = line.Length - line.TrimEnd().Length;
            var leading = leadingLength == 0 ? string.Empty : line[..leadingLength];
            var trailing = trailingLength == 0 ? string.Empty : line[^trailingLength..];
            lines[index] = leading + RewriteUri(line.Trim(), baseUri, relayPrefix, itemId) + trailing;
        }

        var rewrittenPlaylist = string.Join('\n', lines);
        if (hasTrailingNewline && !rewrittenPlaylist.EndsWith('\n'))
        {
            rewrittenPlaylist += "\n";
        }
        return rewrittenPlaylist;
    }

    private static string RewriteUri(string value, Uri baseUri, string relayPrefix, string itemId)
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
        if (!KaevoPlaybackSecurity.IsHlsSessionResourcePath(path, itemId))
        {
            throw new InvalidOperationException("playlistUriNotAllowed");
        }

        return relayPrefix + resolved.PathAndQuery;
    }

    [GeneratedRegex("URI=\"([^\"]+)\"", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UriAttributeRegex();
}
