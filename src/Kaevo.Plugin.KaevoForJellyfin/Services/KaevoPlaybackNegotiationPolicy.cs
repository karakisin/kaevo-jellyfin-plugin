using System.Text.Json;
using System.Text.RegularExpressions;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

internal sealed record KaevoPlaybackNegotiationPolicy(string MediaSourceId, int SubtitleStreamIndex)
{
    public static KaevoPlaybackNegotiationPolicy FromAuthorizedItem(JsonElement item, int? selectedSubtitle)
    {
        if (item.ValueKind != JsonValueKind.Object
            || selectedSubtitle is < 0
            || !item.TryGetProperty("MediaSources", out var sources)
            || sources.ValueKind != JsonValueKind.Array || sources.GetArrayLength() == 0
            || sources[0].ValueKind != JsonValueKind.Object
            || !sources[0].TryGetProperty("Id", out var id) || id.ValueKind != JsonValueKind.String
            || id.GetString() is not { } sourceId
            || !Regex.IsMatch(sourceId, "^[A-Za-z0-9._:-]{1,128}$", RegexOptions.CultureInvariant))
            throw new InvalidOperationException("playbackSourceUnavailable");
        // Null in Kaevo means subtitles off. Null in Jellyfin means choose
        // the user's default, which may force a subtitle burn-in transcode.
        return new(sourceId, selectedSubtitle ?? -1);
    }
}
