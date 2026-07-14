namespace Kaevo.Plugin.KaevoForJellyfin.Models;

public sealed record KaevoStatusResponse(
    string Status,
    string Plugin,
    string Version,
    bool CloudRelay);

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
