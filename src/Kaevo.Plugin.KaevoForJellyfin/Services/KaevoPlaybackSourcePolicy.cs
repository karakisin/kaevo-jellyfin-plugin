using System.Text.Json;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

internal static class KaevoPlaybackSourcePolicy
{
    public static bool IsDiscImage(JsonElement source)
    {
        var container = source.TryGetProperty("Container", out var containerValue)
            ? containerValue.GetString()
            : null;
        if (string.Equals(container?.Trim(), "iso", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var path = source.TryGetProperty("Path", out var pathValue)
            ? pathValue.GetString()
            : null;
        return path?.EndsWith(".iso", StringComparison.OrdinalIgnoreCase) == true;
    }
}
