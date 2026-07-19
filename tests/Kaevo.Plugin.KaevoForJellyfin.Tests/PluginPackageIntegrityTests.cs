using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class PluginPackageIntegrityTests
{
    [Fact]
    public void MatchingJellyfinPackageDirectoryIsAccepted()
        => Assert.True(KaevoPackageIntegrity.IsValidVersion(new Version(0, 2, 49, 0), "/config/plugins/Kaevo_0.2.49.0/Kaevo.Plugin.KaevoForJellyfin.dll"));

    [Theory]
    [InlineData("/config/plugins/Kaevo_0.2.50.0/Kaevo.Plugin.KaevoForJellyfin.dll")]
    [InlineData("/config/plugins/Kaevo_invalid/Kaevo.Plugin.KaevoForJellyfin.dll")]
    public void MismatchedOrMalformedPackageDirectoryFailsClosed(string path)
        => Assert.False(KaevoPackageIntegrity.IsValidVersion(new Version(0, 2, 49, 0), path));

    [Fact]
    public void BuildAndTestDirectoriesDoNotPretendToBeJellyfinPackages()
        => Assert.True(KaevoPackageIntegrity.IsValidVersion(new Version(0, 2, 49, 0), "/workspace/bin/Release/net8.0/Kaevo.Plugin.KaevoForJellyfin.dll"));
}
