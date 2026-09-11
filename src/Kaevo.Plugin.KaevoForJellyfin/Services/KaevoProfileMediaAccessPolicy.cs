using System.Text.Json;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

// Read-only verification of one exact account. Never widen libraries, remove
// parental restrictions, enable a disabled user, or substitute the server owner.
internal static class KaevoProfileMediaAccessPolicy
{
    internal static bool PlaybackReady(JsonElement user, string exactUserId)
    {
        if (user.ValueKind != JsonValueKind.Object
            || !user.TryGetProperty("Id", out var id) || id.ValueKind != JsonValueKind.String
            || !KaevoProfileJellyfinBindingStore.TryNormalizeJellyfinUserId(id.GetString(), out var normalized)
            || normalized != exactUserId || !user.TryGetProperty("Policy", out var policy)
            || policy.ValueKind != JsonValueKind.Object
            || !policy.TryGetProperty("IsDisabled", out var disabled) || disabled.ValueKind != JsonValueKind.False)
            return false;
        return new[] { "EnableMediaPlayback", "EnablePlaybackRemuxing",
            "EnableAudioPlaybackTranscoding", "EnableVideoPlaybackTranscoding" }
            .All(key => policy.TryGetProperty(key, out var value) && value.ValueKind == JsonValueKind.True);
    }
}
