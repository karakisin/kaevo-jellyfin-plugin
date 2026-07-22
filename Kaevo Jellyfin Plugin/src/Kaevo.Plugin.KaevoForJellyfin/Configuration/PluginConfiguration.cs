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

    // Disabled until Cloud, Plugin, and iOS V3 are jointly validated. This is
    // deliberately separate from legacy pairing so V3 never silently falls back.
    public bool PairingV3Enabled { get; set; }

    // Public verification keys only. Production authorization-signing private
    // material is never stored in plugin configuration.
    public string PairingV3CloudAuthorizationVerificationKeysJson { get; set; } = string.Empty;

    // The issuer is an explicit deployment binding, not a user-supplied
    // routing value. Empty means V3 remains fail-closed.
    public string PairingV3CloudAuthorizationIssuer { get; set; } = string.Empty;
}
