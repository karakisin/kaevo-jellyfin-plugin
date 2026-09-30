using System.Globalization;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class HlsStartPreferenceTests
{
    [Fact]
    public void ResumePreferencePreservesFullTimelineAndMediaUris()
    {
        const string media = "#EXTM3U\n#EXT-X-VERSION:7\n#EXTINF:2,\n0.ts?scope=exact\n#EXTINF:2,\n1.ts?scope=exact\n#EXT-X-ENDLIST\n";
        var result = KaevoHlsStartPreference.Apply(media, 9_151_234_567);
        Assert.StartsWith("#EXTM3U\n#EXT-X-START:TIME-OFFSET=915.1234567,PRECISE=YES\n", result);
        Assert.EndsWith(media[8..], result);
        Assert.Equal(result, KaevoHlsStartPreference.Apply(result, 9_151_234_567));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(long.MaxValue)]
    public void InvalidOrStartOverPositionDoesNotChangePlaylist(long ticks)
    {
        const string value = "#EXTM3U\n#EXTINF:2,\n0.ts\n";
        Assert.Equal(value, KaevoHlsStartPreference.Apply(value, ticks));
    }

    [Fact]
    public void StartPreferenceUsesInvariantDecimalAndReplacesExistingHint()
    {
        var previous = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("fr-FR");
            var result = KaevoHlsStartPreference.Apply("#EXTM3U\r\n#EXT-X-START:TIME-OFFSET=1\r\n#EXT-X-STREAM-INF:BANDWIDTH=1\r\nmain.m3u8\r\n", 12_500_000);
            Assert.Contains("TIME-OFFSET=1.25,PRECISE=YES", result);
            Assert.Equal(1, result.Split("#EXT-X-START:").Length - 1);
            Assert.EndsWith("main.m3u8\n", result);
        }
        finally { CultureInfo.CurrentCulture = previous; }
    }
}
