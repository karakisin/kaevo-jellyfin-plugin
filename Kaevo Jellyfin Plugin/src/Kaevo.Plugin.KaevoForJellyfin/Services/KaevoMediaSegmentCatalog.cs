using System.Text.Json;
using System.Text.Json.Serialization;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

internal static class KaevoMediaSegmentCatalog
{
    private const int MaximumSegments = 32;
    private const long MaximumSegmentTicks = 18_000_000_000;

    internal static IReadOnlyList<KaevoMediaSegmentProjection> FromJellyfin(JsonElement root, string expectedItemId)
    {
        if (root.ValueKind != JsonValueKind.Object
            || !root.TryGetProperty("Items", out var items)
            || items.ValueKind != JsonValueKind.Array)
        {
            return Array.Empty<KaevoMediaSegmentProjection>();
        }

        var result = new List<KaevoMediaSegmentProjection>();
        foreach (var item in items.EnumerateArray())
        {
            if (result.Count >= MaximumSegments || item.ValueKind != JsonValueKind.Object)
            {
                break;
            }
            var itemId = StringValue(item, "ItemId");
            var id = StringValue(item, "Id");
            var type = SegmentType(item);
            var startTicks = Int64Value(item, "StartTicks");
            var endTicks = Int64Value(item, "EndTicks");
            if (!string.Equals(itemId, expectedItemId, StringComparison.OrdinalIgnoreCase)
                || (type != "Intro" && type != "Recap")
                || startTicks is null
                || endTicks is null)
            {
                continue;
            }
            var boundedStartTicks = startTicks.Value;
            var boundedEndTicks = endTicks.Value;
            if (boundedStartTicks < 0
                || boundedEndTicks <= boundedStartTicks
                || boundedEndTicks - boundedStartTicks > MaximumSegmentTicks)
            {
                continue;
            }
            result.Add(new KaevoMediaSegmentProjection(
                string.IsNullOrWhiteSpace(id) ? $"{itemId}:{type}:{boundedStartTicks}:{boundedEndTicks}" : id,
                itemId!,
                type,
                boundedStartTicks,
                boundedEndTicks));
        }
        return result;
    }

    private static string SegmentType(JsonElement item)
    {
        if (!item.TryGetProperty("Type", out var value))
        {
            return "Unknown";
        }
        if (value.ValueKind == JsonValueKind.String)
        {
            var type = value.GetString();
            if (string.Equals(type, "Intro", StringComparison.OrdinalIgnoreCase)) return "Intro";
            if (string.Equals(type, "Recap", StringComparison.OrdinalIgnoreCase)) return "Recap";
        }
        if (value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out var ordinal))
        {
            return ordinal switch { 3 => "Recap", 5 => "Intro", _ => "Unknown" };
        }
        return "Unknown";
    }

    private static string? StringValue(JsonElement item, string property) =>
        item.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static long? Int64Value(JsonElement item, string property) =>
        item.TryGetProperty(property, out var value) && value.TryGetInt64(out var result)
            ? result
            : null;
}

internal sealed record KaevoMediaSegmentProjection(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("item_id")] string ItemId,
    [property: JsonPropertyName("type")] string Type,
    [property: JsonPropertyName("start_ticks")] long StartTicks,
    [property: JsonPropertyName("end_ticks")] long EndTicks);
