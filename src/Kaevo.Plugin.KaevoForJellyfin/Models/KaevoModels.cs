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

public sealed record KaevoLifecyclePairRequest(
    string CloudBaseUrl,
    string OwnerAccessToken,
    string ProfileId,
    string JellyfinUserId,
    string JellyfinAccessToken);

public sealed record KaevoLifecycleOwnerRequest(string OwnerAccessToken);

public sealed record KaevoLifecycleResponse(string State, int CredentialVersion);

public sealed record KaevoLocalPairingStartResponse(
    string Code,
    DateTimeOffset ExpiresAtUtc,
    string PairingUri,
    string QrPngBase64);

public sealed record KaevoLocalPairingClaimRequest(
    string Code,
    string CloudBaseUrl,
    string OwnerAccessToken,
    string ProfileId,
    string JellyfinUserId,
    string JellyfinAccessToken);

public sealed record KaevoPairingV3StartRequest(
    string JellyfinServerId,
    string JellyfinServerName,
    string JellyfinSetupUserId);

// The QR image is returned only to the elevated local Jellyfin administrator
// who created the one-time ticket. It is never logged or persisted by the UI.
public sealed record KaevoPairingV3StartResponse(
    string Protocol,
    DateTimeOffset ExpiresAtUtc,
    string QrPngBase64);

/// <summary>
/// Deliberately minimal local-administrator status. It confirms only whether
/// this plugin has a completed V3 connector; it never exposes QR, identity,
/// authorization, or connector-binding material.
/// </summary>
public sealed record KaevoPairingV3StatusResponse(
    string State,
    string Protocol,
    bool RequiresReauthentication);

public sealed record KaevoPairingV3ChallengeRequest(
    string Protocol,
    string TicketId,
    string PairingAttemptId,
    string PairingAuthorizationHash,
    string CorrelationId);

public sealed record KaevoPairingV3CompleteRequest(
    string Protocol,
    string TicketId,
    string PairingAttemptId,
    string ChallengeId,
    string ChallengeNonce,
    string ChallengeResponseSignature,
    string Authorization,
    string JellyfinUserId,
    string CorrelationId);

// This is deliberately an explicit recovery operation, not normal-path
// polling. It is used only after a reserved attempt has an ambiguous outcome.
public sealed record KaevoPairingV3RecoveryRequest(
    string TicketId,
    string CorrelationId);

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
