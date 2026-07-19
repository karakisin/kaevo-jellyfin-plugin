namespace Kaevo.Plugin.KaevoForJellyfin.Services;

internal static class KaevoPackageIntegrity
{
    internal static bool IsValidVersion(Version? assemblyVersion, string assemblyLocation)
    {
        var directory = Path.GetFileName(Path.GetDirectoryName(assemblyLocation));
        if (string.IsNullOrEmpty(directory) || !directory.StartsWith("Kaevo_", StringComparison.Ordinal)) return true;
        var declared = directory["Kaevo_".Length..];
        return assemblyVersion is not null && Version.TryParse(declared, out var packageVersion)
            && packageVersion == assemblyVersion;
    }
}
