using System.Text.Json;
using System.Text.Json.Serialization;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

internal sealed record KaevoPlaybackTrack(
    [property: JsonPropertyName("stream_index")] int StreamIndex,
    [property: JsonPropertyName("kind")] string Kind,
    [property: JsonPropertyName("title")] string Title,
    [property: JsonPropertyName("language")] string? Language,
    [property: JsonPropertyName("codec")] string? Codec,
    [property: JsonPropertyName("channels")] int? Channels,
    [property: JsonPropertyName("is_default")] bool IsDefault,
    [property: JsonPropertyName("is_forced")] bool IsForced,
    [property: JsonPropertyName("is_external")] bool IsExternal,
    [property: JsonPropertyName("is_text_subtitle")] bool IsTextSubtitle);

internal sealed record KaevoPlaybackTrackCatalog(
    IReadOnlyList<KaevoPlaybackTrack> AudioTracks,
    IReadOnlyList<KaevoPlaybackTrack> SubtitleTracks,
    int? SelectedAudioStreamIndex,
    int? SelectedSubtitleStreamIndex)
{
    public static KaevoPlaybackTrackCatalog FromMediaSource(JsonElement source)
    {
        var audio = new List<KaevoPlaybackTrack>();
        var subtitles = new List<KaevoPlaybackTrack>();
        if (source.TryGetProperty("MediaStreams", out var streams)
            && streams.ValueKind == JsonValueKind.Array)
        {
            foreach (var stream in streams.EnumerateArray())
            {
                if (!TryInt(stream, "Index", out var index) || index < 0)
                {
                    continue;
                }

                var type = String(stream, "Type")?.ToLowerInvariant();
                if (type is not ("audio" or "subtitle"))
                {
                    continue;
                }

                var language = SafeText(String(stream, "Language"), 24);
                var codec = SafeText(String(stream, "Codec"), 32);
                var title = SafeText(String(stream, "DisplayTitle"), 160)
                    ?? SafeText(String(stream, "Title"), 160)
                    ?? language
                    ?? (type == "audio" ? $"Audio {index}" : $"Subtitles {index}");
                var track = new KaevoPlaybackTrack(
                    index,
                    type,
                    title,
                    language,
                    codec,
                    TryInt(stream, "Channels", out var channels) && channels is > 0 and <= 64 ? channels : null,
                    Boolean(stream, "IsDefault"),
                    Boolean(stream, "IsForced"),
                    Boolean(stream, "IsExternal"),
                    Boolean(stream, "IsTextSubtitleStream"));
                if (type == "audio" && audio.Count < 32)
                {
                    audio.Add(track);
                }
                else if (type == "subtitle" && subtitles.Count < 64)
                {
                    subtitles.Add(track);
                }
            }
        }

        var selectedAudio = NullableInt(source, "DefaultAudioStreamIndex")
            ?? audio.FirstOrDefault(track => track.IsDefault)?.StreamIndex
            ?? audio.FirstOrDefault()?.StreamIndex;
        var selectedSubtitle = NullableInt(source, "DefaultSubtitleStreamIndex");
        return new KaevoPlaybackTrackCatalog(audio, subtitles, selectedAudio, selectedSubtitle);
    }

    private static string? String(JsonElement value, string name)
        => value.TryGetProperty(name, out var property) && property.ValueKind == JsonValueKind.String
            ? property.GetString()
            : null;

    private static bool Boolean(JsonElement value, string name)
        => value.TryGetProperty(name, out var property)
            && property.ValueKind is JsonValueKind.True or JsonValueKind.False
            && property.GetBoolean();

    private static bool TryInt(JsonElement value, string name, out int result)
    {
        result = 0;
        return value.TryGetProperty(name, out var property) && property.TryGetInt32(out result);
    }

    private static int? NullableInt(JsonElement value, string name)
        => TryInt(value, name, out var result) ? result : null;

    private static string? SafeText(string? value, int maximumLength)
    {
        var result = value?.Trim();
        if (string.IsNullOrEmpty(result))
        {
            return null;
        }
        return result.Length <= maximumLength ? result : result[..maximumLength];
    }
}
