using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class CloudStateTests
{
    [Fact]
    public void RelayRemainsOnlineWhileAnyPooledChannelIsConnected()
    {
        var state = new KaevoCloudState();
        state.RelayConnected();
        state.RelayConnected();
        state.RelayConnected();

        state.RelayDisconnected();
        state.RelayDisconnected();

        var relay = state.RelaySnapshot();
        Assert.Equal("online", relay.Status);
        Assert.Equal(1, relay.ConnectedChannels);

        state.RelayDisconnected();
        relay = state.RelaySnapshot();
        Assert.Equal("reconnecting", relay.Status);
        Assert.Equal(0, relay.ConnectedChannels);
    }

    [Fact]
    public void OneChannelErrorDoesNotHideHealthyRelayPool()
    {
        var state = new KaevoCloudState();
        state.RelayConnected();
        state.SetRelayError("relayDisconnected");

        var relay = state.RelaySnapshot();
        Assert.Equal("online", relay.Status);
        Assert.Equal("relayDisconnected", relay.LastError);
    }
}
