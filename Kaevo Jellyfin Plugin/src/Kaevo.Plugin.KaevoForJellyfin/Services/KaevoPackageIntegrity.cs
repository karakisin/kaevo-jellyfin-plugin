namespace Kaevo.Plugin.KaevoForJellyfin.Services;

internal static class KaevoPackageIntegrity
{
    internal static void ValidateVersion(Version? assemblyVersion, string assemblyLocation)
    {
        var directory = Path.GetFileName(Path.GetDirectoryName(assemblyLocation));
        if (string.IsNullOrEmpty(directory) || !directory.StartsWith("Kaevo_", StringComparison.Ordinal)) return;
        var declared = directory["Kaevo_".Length..];
        if (assemblyVersion is null || !Version.TryParse(declared, out var packageVersion)
            || packageVersion != assemblyVersion)
        {
            throw new InvalidOperationException("pluginPackageVersionMismatch");
        }
    }
}
