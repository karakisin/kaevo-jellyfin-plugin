using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class LocalPairingServiceTests
{
    [Fact]
    public void TicketIsSingleUseAndAcceptsNormalizedCode()
    {
        var service = new KaevoLocalPairingService();
        var ticket = service.Start();

        Assert.Matches("^[0-9A-F]{5}-[0-9A-F]{5}$", ticket.Code);
        Assert.True(service.Consume(ticket.Code.ToLowerInvariant().Replace("-", string.Empty)));
        Assert.False(service.Consume(ticket.Code));
    }

    [Fact]
    public void StartingNewTicketInvalidatesPreviousTicket()
    {
        var service = new KaevoLocalPairingService();
        var first = service.Start();
        var second = service.Start();

        Assert.False(service.Consume(first.Code));
        Assert.True(service.Consume(second.Code));
    }
}
