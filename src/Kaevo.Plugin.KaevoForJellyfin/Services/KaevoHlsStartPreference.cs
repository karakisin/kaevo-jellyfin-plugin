using System.Globalization;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

internal static class KaevoHlsStartPreference
{
    internal static string Apply(string playlist, long positionTicks)
    {
        if (positionTicks <= 0 || positionTicks > 60_000L * 10_000_000) return playlist;
        var lines = playlist.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
        if (lines.Length == 0 || lines[0] != "#EXTM3U") return playlist;
        var seconds = (positionTicks / 10_000_000m).ToString("0.#######", CultureInfo.InvariantCulture);
        // Do not alter segment durations, numbering, media URIs or the source
        // timeline. Compact relative timelines are excluded by the caller.
        return "#EXTM3U\n#EXT-X-START:TIME-OFFSET=" + seconds + ",PRECISE=YES\n"
            + string.Join('\n', lines.Skip(1).Where(line => !line.StartsWith("#EXT-X-START:", StringComparison.Ordinal)));
    }
}
