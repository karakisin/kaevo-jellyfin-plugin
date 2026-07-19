namespace Kaevo.Plugin.KaevoForJellyfin.Services;

public sealed class KaevoCloudState
{
    private readonly object _gate = new();
    private string _status = "disabled";
    private string? _lastError;
    private DateTimeOffset? _lastHeartbeatUtc;
    private string _relayStatus = "disabled";
    private string? _relayError;
    private DateTimeOffset? _lastRelayConnectedUtc;
    private int _relayConnectedChannels;
    private CancellationTokenSource _configurationChanged = new();

    public CancellationToken ConfigurationChangedToken()
    {
        lock (_gate)
        {
            return _configurationChanged.Token;
        }
    }

    public void SignalConfigurationChanged()
    {
        CancellationTokenSource previous;
        lock (_gate)
        {
            previous = _configurationChanged;
            _configurationChanged = new CancellationTokenSource();
        }
        previous.Cancel();
        previous.Dispose();
    }

    public (string Status, string? LastError, DateTimeOffset? LastHeartbeatUtc) Snapshot()
    {
        lock (_gate)
        {
            return (_status, _lastError, _lastHeartbeatUtc);
        }
    }

    public (string Status, string? LastError, DateTimeOffset? LastConnectedUtc, int ConnectedChannels) RelaySnapshot()
    {
        lock (_gate)
        {
            return (_relayStatus, _relayError, _lastRelayConnectedUtc, _relayConnectedChannels);
        }
    }

    public void Set(string status, string? error = null, bool heartbeat = false)
    {
        lock (_gate)
        {
            _status = status;
            _lastError = error;
            if (heartbeat)
            {
                _lastHeartbeatUtc = DateTimeOffset.UtcNow;
            }
        }
    }

    public void SetRelay(string status, string? error = null, bool connected = false)
    {
        lock (_gate)
        {
            _relayStatus = status;
            _relayError = error;
            if (status == "disabled")
            {
                _relayConnectedChannels = 0;
            }
            if (connected)
            {
                _lastRelayConnectedUtc = DateTimeOffset.UtcNow;
            }
        }
    }

    public void RelayConnected()
    {
        lock (_gate)
        {
            _relayConnectedChannels++;
            _relayStatus = "online";
            _relayError = null;
            _lastRelayConnectedUtc = DateTimeOffset.UtcNow;
        }
    }

    public void RelayDisconnected()
    {
        lock (_gate)
        {
            _relayConnectedChannels = Math.Max(0, _relayConnectedChannels - 1);
            if (_relayConnectedChannels == 0)
            {
                _relayStatus = "reconnecting";
            }
        }
    }

    public void SetRelayError(string error)
    {
        lock (_gate)
        {
            _relayError = error;
            if (_relayConnectedChannels == 0)
            {
                _relayStatus = "reconnecting";
            }
        }
    }
}
