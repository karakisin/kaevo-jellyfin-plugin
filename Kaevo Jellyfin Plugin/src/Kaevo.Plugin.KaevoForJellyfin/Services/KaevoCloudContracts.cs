using System.Text.Json;
using System.Text.Json.Serialization;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

internal sealed record PairingExchangeRequest(
    [property: JsonPropertyName("connector_id")] string ConnectorId,
    [property: JsonPropertyName("pairing_code")] string PairingCode);

internal sealed record PairingExchangeResponse(
    [property: JsonPropertyName("state")] string State,
    [property: JsonPropertyName("connector_id")] string ConnectorId,
    [property: JsonPropertyName("profile_id")] string ProfileId,
    [property: JsonPropertyName("connector_token")] string ConnectorToken,
    [property: JsonPropertyName("playback_grant_key")] string PlaybackGrantKey);

internal sealed record CloudClaimResponse(
    [property: JsonPropertyName("state")] string State,
    [property: JsonPropertyName("request")] CloudRequest? Request);

internal sealed record ConnectorRegistrationResponse(
    [property: JsonPropertyName("state")] string State,
    [property: JsonPropertyName("playback")] ConnectorPlaybackConfiguration? Playback);

internal sealed record ConnectorPlaybackConfiguration(
    [property: JsonPropertyName("enabled")] bool Enabled,
    [property: JsonPropertyName("relay_websocket_url")] string RelayWebSocketUrl);

internal sealed record CloudRequest(
    [property: JsonPropertyName("request_id")] string RequestId,
    [property: JsonPropertyName("method")] string Method,
    [property: JsonPropertyName("provider")] string Provider,
    [property: JsonPropertyName("path")] string Path,
    [property: JsonPropertyName("query")] Dictionary<string, JsonElement>? Query,
    [property: JsonPropertyName("operation")] string? Operation,
    [property: JsonPropertyName("parameters")] Dictionary<string, JsonElement>? Parameters);

internal sealed record RelayTicketResponse(
    [property: JsonPropertyName("relay_ticket")] string RelayTicket);

internal sealed record RelayMessage(
    [property: JsonPropertyName("type")] string Type,
    [property: JsonPropertyName("request_id")] string RequestId,
    [property: JsonPropertyName("grant")] string? Grant,
    [property: JsonPropertyName("method")] string? Method,
    [property: JsonPropertyName("path")] string? Path,
    [property: JsonPropertyName("query")] Dictionary<string, JsonElement>? Query,
    [property: JsonPropertyName("range")] string? Range);
