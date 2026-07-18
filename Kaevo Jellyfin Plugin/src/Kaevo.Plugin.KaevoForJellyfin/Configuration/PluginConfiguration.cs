using MediaBrowser.Model.Plugins;

namespace Kaevo.Plugin.KaevoForJellyfin.Configuration;

public sealed class PluginConfiguration : BasePluginConfiguration
{
    public int SnapshotItemLimit { get; set; } = 50;

    public bool CloudConnectorEnabled { get; set; }

    public string CloudBaseUrl { get; set; } = string.Empty;

    public string RelayWebSocketUrl { get; set; } = string.Empty;

    public string ProfileId { get; set; } = string.Empty;

    public string ConnectorId { get; set; } = string.Empty;

    public string PairingCode { get; set; } = string.Empty;

    public string LocalJellyfinBaseUrl { get; set; } = "http://127.0.0.1:8096";

    public string JellyfinUserId { get; set; } = string.Empty;

    public bool RemoteMetadataEnabled { get; set; } = true;

    public bool RemoteArtworkEnabled { get; set; } = true;

    public bool RemoteWritesEnabled { get; set; }

    public bool RemoteMediaDeletionEnabled { get; set; }

    public bool RemotePlaybackEnabled { get; set; }

    public bool MediaScanEnabled { get; set; } = true;

    public bool OptimizerPlanningEnabled { get; set; } = true;

    public bool OptimizerExecutionEnabled { get; set; }

    public int MaximumPlaybackBitrate { get; set; } = 40_000_000;

    public int MaximumRemoteResponseBytes { get; set; } = 2_000_000;
}
