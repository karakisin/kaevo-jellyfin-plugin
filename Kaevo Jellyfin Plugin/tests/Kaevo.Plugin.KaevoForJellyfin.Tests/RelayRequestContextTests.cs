using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class RelayRequestContextTests
{
    [Fact]
    public void LateRelayMessagesAfterRequestCleanupAreIgnored()
    {
        var context = new KaevoCloudConnectorService.RelayRequestContext(CancellationToken.None);
        context.Dispose();

        context.AcknowledgeBody();
        context.Cancel();
    }

    [Fact]
    public async Task DuplicateBodyAcknowledgementKeepsSingleChunkWindow()
    {
        using var context = new KaevoCloudConnectorService.RelayRequestContext(CancellationToken.None);

        context.AcknowledgeBody();
        context.AcknowledgeBody();

        Assert.True(await context.WaitForBodyAcknowledgementAsync(TimeSpan.FromMilliseconds(100)));
        Assert.False(await context.WaitForBodyAcknowledgementAsync(TimeSpan.FromMilliseconds(20)));
    }
}
