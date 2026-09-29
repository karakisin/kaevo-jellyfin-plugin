using System.Text.Json;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

internal static class KaevoPlaybackProfilePolicy
{
    private const int MaximumRemoteBitrate = 40_000_000;

    public static int ClampRemoteBitrate(int configuredMaximum, int? requestedMaximum)
    {
        var ceiling = Math.Clamp(configuredMaximum, 1_000_000, MaximumRemoteBitrate);
        return requestedMaximum.HasValue
            ? Math.Clamp(requestedMaximum.Value, 1_000_000, ceiling)
            : ceiling;
    }

    public static object BuildAppleHlsDeviceProfile(int maximumBitrate, bool preferDirectPlay = false) => new
    {
        Name = "Kaevo Apple HLS",
        MaxStreamingBitrate = maximumBitrate,
        MaxStaticBitrate = maximumBitrate,
        DirectPlayProfiles = preferDirectPlay ? new object[]
        {
            new { Container = "mp4,m4v,mov", Type = "Video", VideoCodec = "h264,hevc", AudioCodec = "aac,ac3,eac3" }
        } : Array.Empty<object>(),
        CodecProfiles = preferDirectPlay ? new object[]
        {
            new { Type = "Video", Codec = "h264", Conditions = new[]
            {
                Condition("VideoProfile", "EqualsAny", "baseline|constrained baseline|main|high"),
                Condition("VideoBitDepth", "LessThanEqual", "8"),
                Condition("VideoLevel", "LessThanEqual", "52"),
                Condition("Width", "LessThanEqual", "3840"),
                Condition("Height", "LessThanEqual", "2160")
            } },
            new { Type = "Video", Codec = "hevc", Conditions = new[]
            {
                Condition("VideoProfile", "EqualsAny", "main|main 10"),
                Condition("VideoBitDepth", "LessThanEqual", "10"),
                // Do not claim Dolby Vision P7 or unverified DV combinations.
                Condition("VideoRangeType", "EqualsAny", "SDR|HDR10|HLG"),
                Condition("Width", "LessThanEqual", "3840"),
                Condition("Height", "LessThanEqual", "2160")
            } }
        } : Array.Empty<object>(),
        TranscodingProfiles = new[]
        {
            // Apple platforms support H.264 and HEVC in fragmented MP4 HLS.
            // Advertising fMP4 lets Jellyfin copy compatible HEVC video while
            // converting unsupported audio to AAC. This also avoids invoking a
            // hardware video encoder when video conversion is unnecessary.
            new
            {
                Container = "mp4",
                Type = "Video",
                VideoCodec = "h264,hevc",
                AudioCodec = "aac",
                Protocol = "hls",
                Context = "Streaming"
            }
        }
    };

    private static object Condition(string property, string condition, string value) =>
        new { Property = property, Condition = condition, Value = value, IsRequired = true };

    public static string SelectMode(JsonElement source, bool preferDirectPlay, bool forceTranscode, bool compatibilityPlayer)
    {
        if (forceTranscode) return "transcode";
        if (compatibilityPlayer) return "direct_play";
        if (Supported(source, "SupportsDirectPlay"))
        {
            // Jellyfin has validated the codecs against our native profile.
            // A streaming preference still needs those capability checks: an
            // empty direct profile otherwise forces needless video encoding.
            // Apple recommends hvc1 sample entries. Repackage hev1 rather than
            // sending an original file that AVPlayer may play as audio only.
            return preferDirectPlay && !RequiresAppleHevcRepackaging(source)
                ? "direct_play" : "remux";
        }
        return Supported(source, "SupportsDirectStream") ? "remux" : "transcode";
    }

    private static bool RequiresAppleHevcRepackaging(JsonElement source)
    {
        if (!source.TryGetProperty("MediaStreams", out var streams)
            || streams.ValueKind != JsonValueKind.Array) return false;
        return streams.EnumerateArray().Any(stream =>
            stream.ValueKind == JsonValueKind.Object
            && stream.TryGetProperty("Type", out var type)
            && string.Equals(type.GetString(), "Video", StringComparison.OrdinalIgnoreCase)
            && stream.TryGetProperty("Codec", out var codec)
            && string.Equals(codec.GetString(), "hevc", StringComparison.OrdinalIgnoreCase)
            && stream.TryGetProperty("CodecTag", out var tag)
            && string.Equals(tag.GetString(), "hev1", StringComparison.OrdinalIgnoreCase));
    }

    private static bool Supported(JsonElement source, string name) =>
        source.ValueKind == JsonValueKind.Object && source.TryGetProperty(name, out var value)
        && value.ValueKind == JsonValueKind.True;

}
