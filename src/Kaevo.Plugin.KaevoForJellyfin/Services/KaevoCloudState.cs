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

    public (string Status, string? LastError, DateTimeOffset? LastHeartbeatUtc) Snapshot()
    {
        lock (_gate)
        {
            return (_status, _lastError, _lastHeartbeatUtc);
        }
    }

    public (string Status, string? LastError, DateTimeOffset? LastConnectedUtc) RelaySnapshot()
    {
        lock (_gate)
        {
            return (_relayStatus, _relayError, _lastRelayConnectedUtc);
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
            if (connected)
            {
                _lastRelayConnectedUtc = DateTimeOffset.UtcNow;
            }
        }
    }
}
