using System.IO.Compression;
using System.Text;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public class RelayPlaylistEncodingTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("br")]
    [InlineData("GZIP")]
    public void ExistingRelaysReceiveUnmodifiedPlaylist(string? encoding)
    {
        var body = Encoding.UTF8.GetBytes("#EXTM3U\n#EXTINF:2.0,\nmain/0.mp4\n");
        Assert.Same(body, KaevoCloudConnectorService.EncodeRelayPlaylist(body, encoding));
    }

    [Fact]
    public void NegotiatedCompressionPreservesFullPlaylist()
    {
        var body = Encoding.UTF8.GetBytes("#EXTM3U\n" + string.Concat(Enumerable.Repeat(
            "#EXTINF:2.0,\nmain/0.mp4?MediaSourceId=example\n", 20000)));
        var encoded = KaevoCloudConnectorService.EncodeRelayPlaylist(body, "gzip");
        Assert.True(encoded.Length < body.Length / 50);
        using var input = new MemoryStream(encoded);
        using var gzip = new GZipStream(input, CompressionMode.Decompress);
        using var decoded = new MemoryStream();
        gzip.CopyTo(decoded);
        Assert.Equal(body, decoded.ToArray());
    }
}
