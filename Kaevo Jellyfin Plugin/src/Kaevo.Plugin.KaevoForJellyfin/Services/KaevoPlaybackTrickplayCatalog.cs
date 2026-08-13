using System.Text.Json;
using System.Text.Json.Serialization;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

internal sealed record KaevoPlaybackTrickplayMetadata(
    [property: JsonPropertyName("width")] int Width,
    [property: JsonPropertyName("height")] int Height,
    [property: JsonPropertyName("tile_width")] int TileWidth,
    [property: JsonPropertyName("tile_height")] int TileHeight,
    [property: JsonPropertyName("thumbnail_count")] int ThumbnailCount,
    [property: JsonPropertyName("interval")] int Interval);

/// Extracts only bounded, non-secret trickplay geometry for the exact playback
/// media source. Paths and provider credentials never leave the connector.
internal static class KaevoPlaybackTrickplayCatalog
{
    private const int PreferredWidth = 320;

    public static KaevoPlaybackTrickplayMetadata? FromItem(JsonElement item, string mediaSourceId)
    {
        if (item.ValueKind != JsonValueKind.Object
            || string.IsNullOrWhiteSpace(mediaSourceId)
            || !item.TryGetProperty("Trickplay", out var trickplay)
            || trickplay.ValueKind != JsonValueKind.Object
            || !trickplay.TryGetProperty(mediaSourceId, out var source)
            || source.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        return source.EnumerateObject()
            .Select(candidate => TryMetadata(candidate.Name, candidate.Value))
            .Where(candidate => candidate is not null)
            .OrderBy(candidate => Math.Abs(candidate!.Width - PreferredWidth))
            .ThenBy(candidate => candidate!.Width)
            .FirstOrDefault();
    }

    private static KaevoPlaybackTrickplayMetadata? TryMetadata(string widthKey, JsonElement value)
    {
        if (!int.TryParse(widthKey, out var width)
            || width is <= 0 or > 8192
            || value.ValueKind != JsonValueKind.Object
            || !TryPositiveInt(value, "Width", 8192, out var declaredWidth)
            || declaredWidth != width
            || !TryPositiveInt(value, "Height", 8192, out var height)
            || !TryPositiveInt(value, "TileWidth", 100, out var tileWidth)
            || !TryPositiveInt(value, "TileHeight", 100, out var tileHeight)
            || !TryPositiveInt(value, "ThumbnailCount", 1_000_000, out var thumbnailCount)
            || !TryPositiveInt(value, "Interval", 3_600_000, out var interval))
        {
            return null;
        }

        return new KaevoPlaybackTrickplayMetadata(
            width,
            height,
            tileWidth,
            tileHeight,
            thumbnailCount,
            interval);
    }

    private static bool TryPositiveInt(JsonElement value, string name, int maximum, out int result)
    {
        result = 0;
        return value.TryGetProperty(name, out var property)
            && property.TryGetInt32(out result)
            && result is > 0
            && result <= maximum;
    }
}
