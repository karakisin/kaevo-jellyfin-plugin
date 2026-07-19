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

    public static object BuildAppleHlsDeviceProfile(int maximumBitrate) => new
    {
        Name = "Kaevo Apple HLS",
        MaxStreamingBitrate = maximumBitrate,
        DirectPlayProfiles = Array.Empty<object>(),
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
}
