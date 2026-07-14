namespace Kaevo.Plugin.KaevoForJellyfin.Services;

public sealed class KaevoCloudState
{
    private readonly object _gate = new();
    private string _status = "disabled";
    private string? _lastError;
    private DateTimeOffset? _lastHeartbeatUtc;

    public (string Status, string? LastError, DateTimeOffset? LastHeartbeatUtc) Snapshot()
    {
        lock (_gate)
        {
            return (_status, _lastError, _lastHeartbeatUtc);
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
}
