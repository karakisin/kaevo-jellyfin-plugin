namespace Kaevo.Plugin.KaevoForJellyfin.Services;

// A dependency elimination, not a codec, quality, probe or buffer override.
// Keep the original argument string byte-for-byte except one proven-unused
// device declaration. Unknown syntax/pipelines keep Jellyfin's original plan.
internal static class KaevoHardwareDependencyPlan
{
    private sealed record Argument(string Value, int Start, int End);

    internal static string? WithoutUnusedOpenCl(string command)
    {
        var args = Parse(command);
        if (args is null) return null;
        var candidates = Enumerable.Range(0, args.Count - 1)
            .Where(i => args[i].Value == "-init_hw_device" && args[i + 1].Value == "opencl=ocl@va").ToArray();
        if (candidates.Length != 1) return null;
        var candidate = candidates[0];
        var remaining = args.Where((_, i) => i != candidate && i != candidate + 1).ToArray();
        // Includes aliases in options, filters, device derivations and scripts.
        // False negatives (e.g. an unusual filename containing 'ocl') are safe.
        if (remaining.Any(a => a.Value.Contains("opencl", StringComparison.OrdinalIgnoreCase)
            || a.Value.Contains("ocl", StringComparison.OrdinalIgnoreCase)
            || a.Value.StartsWith("-filter_complex", StringComparison.Ordinal)
            || a.Value.StartsWith("-filter_script", StringComparison.Ordinal)
            || a.Value.StartsWith("-/", StringComparison.Ordinal)
            || a.Value == "-lavfi")) return null;
        string? One(string option)
        {
            var indexes = Enumerable.Range(0, args.Count).Where(i => args[i].Value == option).ToArray();
            return indexes.Length == 1 && indexes[0] + 1 < args.Count ? args[indexes[0] + 1].Value : null;
        }
        var devices = Enumerable.Range(0, args.Count - 1).Where(i => args[i].Value == "-init_hw_device")
            .Select(i => args[i + 1].Value).ToArray();
        if (devices.Length != 3 || devices.Count(v => v.StartsWith("vaapi=va:", StringComparison.Ordinal)) != 1
            || !devices.Contains("qsv=qs@va") || One("-filter_hw_device") != "qs"
            || One("-hwaccel") != "vaapi" || One("-hwaccel_output_format") != "vaapi"
            || One("-codec:v:0") != "h264_qsv" || One("-hls_segment_type") != "mpegts") return null;
        var filter = One("-vf");
        if (filter is null || filter.IndexOfAny(['[', ']', ';']) >= 0
            || !filter.EndsWith(",hwmap=derive_device=qsv,format=qsv", StringComparison.Ordinal)) return null;
        var filters = filter.Split(',').Select(f => f.Split('=', 2)[0]).ToArray();
        string[] allowed = ["setparams", "scale_vaapi", "procamp_vaapi", "tonemap_vaapi", "hwmap", "format"];
        if (!filters.Contains("tonemap_vaapi") || filters.Any(f => !allowed.Contains(f))) return null;
        return command.Remove(args[candidate].Start, args[candidate + 1].End - args[candidate].Start);
    }

    private static List<Argument>? Parse(string command)
    {
        if (command.Length is 0 or > 32768 || command.Any(c => char.IsControl(c) || c == '\\')) return null;
        var result = new List<Argument>();
        for (var i = 0; i < command.Length;)
        {
            if (command[i] == ' ') { i++; continue; }
            var start = i;
            var quoted = false;
            var value = new System.Text.StringBuilder();
            while (i < command.Length && (quoted || command[i] != ' '))
            {
                var c = command[i++];
                if (c == '"') quoted = !quoted;
                else if (c == '\'' && !quoted) return null;
                else value.Append(c);
            }
            if (quoted) return null;
            result.Add(new Argument(value.ToString(), start, i));
        }
        return result.Count > 1 ? result : null;
    }
}
