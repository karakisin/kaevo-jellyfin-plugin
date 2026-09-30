using System.Text.Json;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public class ArtworkBatchBudgetTests
{
    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(5)]
    [InlineData(10)]
    public void WorstCaseBatchFitsCloudInlineRecordWithoutRelyingOnCompression(int count)
    {
        var limit = KaevoCloudConnectorService.ArtworkBatchItemByteLimit(count);
        var random = new Random(817);
        var items = Enumerable.Range(0, count).Select(index =>
        {
            var bytes = new byte[limit];
            random.NextBytes(bytes);
            return new { index, status = "completed", response = new
                { content_type = "image/jpeg", body_base64 = Convert.ToBase64String(bytes) } };
        }).ToArray();
        // Cloud's stored response ceiling is 330,000 bytes. Even incompressible
        // image data fits with room for the surrounding completion envelope.
        Assert.True(JsonSerializer.SerializeToUtf8Bytes(new { items }).Length < 310_000);
    }

    [Fact]
    public void InvalidBatchCountIsRejected()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => KaevoCloudConnectorService.ArtworkBatchItemByteLimit(0));
        Assert.Throws<ArgumentOutOfRangeException>(() => KaevoCloudConnectorService.ArtworkBatchItemByteLimit(11));
    }
}
