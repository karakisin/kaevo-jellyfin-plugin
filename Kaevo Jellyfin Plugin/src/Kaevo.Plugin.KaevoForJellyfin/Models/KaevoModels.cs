namespace Kaevo.Plugin.KaevoForJellyfin.Models;

public sealed record KaevoStatusResponse(
    string Status,
    string Plugin,
    string Version,
    bool CloudRelay,
    string CloudConnectorStatus,
    DateTimeOffset? LastCloudHeartbeatUtc,
    bool RemoteMetadata,
    bool RemoteWrites,
    bool RemotePlayback,
    string PlaybackRelayStatus,
    DateTimeOffset? LastPlaybackRelayConnectedUtc,
    int PlaybackRelayChannels,
    string PlaybackRelayProtocol,
    bool OptimizerExecution);

public sealed record KaevoCloudPairingStatus(
    string State,
    DateTimeOffset? LastHeartbeatUtc,
    string? LastError);

public sealed record KaevoCloudActivationRequest(
    string CloudBaseUrl,
    string ProfileId,
    string ConnectorId,
    string PairingCode,
    string JellyfinUserId,
    string JellyfinAccessToken);

public sealed record KaevoCloudActivationResponse(
    string State,
    string Message);

public sealed record KaevoProviderProvisionRequest(
    string BaseUrl,
    string? ApiKey,
    bool Enabled = true);

public sealed record KaevoProviderProvisionResponse(
    string State,
    string Provider);

public sealed record KaevoProviderStatusResponse(
    string Provider,
    string DisplayName,
    bool Enabled,
    bool Configured,
    string BaseUrl,
    bool RequiresApiKey);

public sealed record KaevoMediaScanResponse(
    int Libraries,
    int Movies,
    int Shows,
    int Collections);

public sealed record KaevoLibraryMetadata(
    string Id,
    string Name,
    string? CollectionType);

public sealed record KaevoItemMetadata(
    string Id,
    string Name,
    string Type,
    int? ProductionYear,
    IReadOnlyDictionary<string, string> ImageTags);

public sealed record KaevoMainSnapshotResponse(
    DateTimeOffset GeneratedAtUtc,
    int ItemLimitPerSection,
    IReadOnlyList<KaevoLibraryMetadata> Libraries,
    IReadOnlyList<KaevoItemMetadata> Movies,
    IReadOnlyList<KaevoItemMetadata> Shows,
    IReadOnlyList<KaevoItemMetadata> Collections,
    IReadOnlyList<KaevoItemMetadata> ContinueWatching);
