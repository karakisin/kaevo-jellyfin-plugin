using System.Text.Json;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

internal static class KaevoPlaybackSourcePolicy
{
    public static bool IsDiscImage(JsonElement source)
    {
        var container = StringValue(source, "Container");
        if (string.Equals(container?.Trim(), "iso", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var path = StringValue(source, "Path");
        return path?.EndsWith(".iso", StringComparison.OrdinalIgnoreCase) == true;
    }

    public static bool SupportsDiscImageHls(JsonElement source)
    {
        // PlaybackInfo must negotiate a usable HLS output with our existing
        // device profile. An ISO filename alone is not a playback capability.
        // Never forward TranscodingUrl: the existing signed, item/source-bound
        // route constructs the URL and keeps provider paths/credentials local.
        var container = StringValue(source, "TranscodingContainer");
        return IsDiscImage(source)
            && source.TryGetProperty("SupportsTranscoding", out var transcode)
            && transcode.ValueKind == JsonValueKind.True
            && string.Equals(StringValue(source, "TranscodingSubProtocol"), "hls", StringComparison.OrdinalIgnoreCase)
            && (string.Equals(container, "mp4", StringComparison.OrdinalIgnoreCase)
                || string.Equals(container, "ts", StringComparison.OrdinalIgnoreCase))
            && !string.IsNullOrWhiteSpace(StringValue(source, "TranscodingUrl"));
    }

    private static string? StringValue(JsonElement source, string name) =>
        source.ValueKind == JsonValueKind.Object
        && source.TryGetProperty(name, out var value)
        && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
}
