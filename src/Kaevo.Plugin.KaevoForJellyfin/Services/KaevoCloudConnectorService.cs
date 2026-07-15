using System.Net;
using System.Net.Http.Headers;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Kaevo.Plugin.KaevoForJellyfin.Configuration;
using MediaBrowser.Controller.Library;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

public sealed partial class KaevoCloudConnectorService : BackgroundService
{
    private const int RemoteArtworkMaximumBytes = 240_000;
    private const int RemoteArtworkMaximumDimension = 2_160;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private static readonly HashSet<string> SafeMetadataQuery = new(StringComparer.OrdinalIgnoreCase)
    {
        "ParentId", "Recursive", "StartIndex", "Limit", "Fields", "EnableUserData", "EnableImages",
        "ImageTypeLimit", "EnableImageTypes", "IncludeItemTypes", "UserId", "seasonId", "isMissing",
        "adjacentTo", "startItemId"
    };

    private readonly KaevoSecretStore _secretStore;
    private readonly KaevoCloudState _state;
    private readonly ILibraryManager _libraryManager;
    private readonly ILogger<KaevoCloudConnectorService> _logger;
    private readonly HttpClient _cloud = new() { Timeout = TimeSpan.FromSeconds(30) };
    private readonly HttpClient _jellyfin = new() { Timeout = TimeSpan.FromSeconds(45) };

    public KaevoCloudConnectorService(
        KaevoSecretStore secretStore,
        KaevoCloudState state,
        ILibraryManager libraryManager,
        ILogger<KaevoCloudConnectorService> logger)
    {
        _secretStore = secretStore;
        _state = state;
        _libraryManager = libraryManager;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var delay = TimeSpan.FromSeconds(1);
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var configuration = CurrentConfiguration();
                if (!configuration.CloudConnectorEnabled)
                {
                    _state.Set("disabled");
                    await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken).ConfigureAwait(false);
                    continue;
                }

                ValidateConfiguration(configuration);
                var secrets = await EnsurePairedAsync(configuration, stoppingToken).ConfigureAwait(false);
                if (string.IsNullOrWhiteSpace(secrets.JellyfinApiKey))
                {
                    throw new InvalidOperationException("jellyfinApiKeyMissing");
                }

                _state.Set("connecting");
                await RegisterAsync(configuration, secrets, stoppingToken).ConfigureAwait(false);
                using var linked = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                var control = RunControlLoopAsync(configuration, secrets, linked.Token);
                var relay = configuration.RemotePlaybackEnabled
                    ? RunRelaySupervisorAsync(configuration, secrets, linked.Token)
                    : Task.Delay(Timeout.Infinite, linked.Token);
                await Task.WhenAny(control, relay).ConfigureAwait(false);
                linked.Cancel();
                await Task.WhenAll(IgnoreCancellation(control), IgnoreCancellation(relay)).ConfigureAwait(false);
                delay = TimeSpan.FromSeconds(1);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception)
            {
                var category = SanitizeError(exception);
                _state.Set("error", category);
                _logger.LogWarning("Kaevo Cloud connector paused: {Category}", category);
                await Task.Delay(delay, stoppingToken).ConfigureAwait(false);
                delay = TimeSpan.FromSeconds(Math.Min(delay.TotalSeconds * 2, 30));
            }
        }
    }

    private async Task<KaevoConnectorSecrets> EnsurePairedAsync(
        PluginConfiguration configuration,
        CancellationToken cancellationToken)
    {
        var existing = await _secretStore.ReadAsync(cancellationToken).ConfigureAwait(false);
        var environmentApiKey = Environment.GetEnvironmentVariable("KAEVO_JELLYFIN_API_KEY")?.Trim() ?? string.Empty;
        var jellyfinCredential = string.IsNullOrWhiteSpace(environmentApiKey)
            ? existing?.JellyfinApiKey ?? string.Empty
            : environmentApiKey;
        if (existing is not null && existing.ConnectorToken.Length >= 24 && existing.PlaybackGrantKey.Length >= 32)
        {
            return existing with { JellyfinApiKey = jellyfinCredential };
        }

        if (string.IsNullOrWhiteSpace(configuration.ConnectorId) || string.IsNullOrWhiteSpace(configuration.PairingCode))
        {
            throw new InvalidOperationException("connectorPairingRequired");
        }

        var response = await SendCloudAsync<PairingExchangeResponse>(
            configuration,
            null,
            HttpMethod.Post,
            "/v1/home-connectors/pairing/exchange",
            new PairingExchangeRequest(configuration.ConnectorId.Trim(), configuration.PairingCode.Trim().ToUpperInvariant()),
            cancellationToken).ConfigureAwait(false);
        if (response.State != "paired" || response.PlaybackGrantKey.Length < 32)
        {
            throw new InvalidOperationException("connectorPairingRejected");
        }

        var secrets = new KaevoConnectorSecrets(response.ConnectorToken, response.PlaybackGrantKey, jellyfinCredential);
        await _secretStore.WriteAsync(secrets, cancellationToken).ConfigureAwait(false);
        configuration.ConnectorId = response.ConnectorId;
        configuration.ProfileId = response.ProfileId;
        configuration.PairingCode = string.Empty;
        KaevoPlugin.Instance?.SaveConfiguration();
        return secrets;
    }

    private async Task RegisterAsync(
        PluginConfiguration configuration,
        KaevoConnectorSecrets secrets,
        CancellationToken cancellationToken)
    {
        var response = await SendCloudAsync<ConnectorRegistrationResponse>(
            configuration,
            secrets,
            HttpMethod.Post,
            "/v1/home-connectors/register",
            new
            {
                connector_id = configuration.ConnectorId,
                profile_id = configuration.ProfileId,
                connector_name = "Kaevo Jellyfin Plugin",
                host_type = "jellyfin_plugin",
                app_version = "0.2.4",
                capabilities = new[]
                {
                    "remote_metadata_v1", "remote_artwork_v1", "remote_commands_v1",
                    "playback_tunnel_v1", "direct_play", "hls_remux", "hls_transcode",
                    "bounded_media_scan_v1", "optimizer_plan_v1"
                },
                provider_status = new
                {
                    jellyfin = ProviderStatus(true, true, "0.2.4", null),
                    playback_tunnel = ProviderStatus(configuration.RemotePlaybackEnabled, configuration.RemotePlaybackEnabled, "0.2.4", configuration.RemotePlaybackEnabled ? null : "disabled")
                }
            },
            cancellationToken).ConfigureAwait(false);
        ApplyPlaybackConfiguration(configuration, response.Playback);
    }

    private async Task RunControlLoopAsync(
        PluginConfiguration configuration,
        KaevoConnectorSecrets secrets,
        CancellationToken cancellationToken)
    {
        var heartbeatAt = DateTimeOffset.MinValue;
        while (!cancellationToken.IsCancellationRequested)
        {
            if (DateTimeOffset.UtcNow >= heartbeatAt)
            {
                await HeartbeatAsync(configuration, secrets, cancellationToken).ConfigureAwait(false);
                heartbeatAt = DateTimeOffset.UtcNow.AddSeconds(60);
            }

            var claim = await SendCloudAsync<CloudClaimResponse>(
                configuration,
                secrets,
                HttpMethod.Post,
                "/v1/remote-requests/claim",
                new { connector_id = configuration.ConnectorId },
                cancellationToken).ConfigureAwait(false);
            if (claim.State != "empty" && claim.Request is not null)
            {
                await HandleClaimAsync(configuration, secrets, claim.Request, cancellationToken).ConfigureAwait(false);
            }

            await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task HeartbeatAsync(
        PluginConfiguration configuration,
        KaevoConnectorSecrets secrets,
        CancellationToken cancellationToken)
    {
        var response = await SendCloudAsync<ConnectorRegistrationResponse>(
            configuration,
            secrets,
            HttpMethod.Post,
            $"/v1/home-connectors/{Uri.EscapeDataString(configuration.ConnectorId)}/heartbeat",
            new
            {
                connector_id = configuration.ConnectorId,
                profile_id = configuration.ProfileId,
                provider_status = new
                {
                    jellyfin = ProviderStatus(true, true, "0.2.4", null),
                    optimizer = ProviderStatus(configuration.OptimizerPlanningEnabled, configuration.OptimizerPlanningEnabled, "0.2.4", configuration.OptimizerPlanningEnabled ? null : "disabled"),
                    playback_tunnel = ProviderStatus(configuration.RemotePlaybackEnabled, configuration.RemotePlaybackEnabled, "0.2.4", configuration.RemotePlaybackEnabled ? null : "disabled")
                }
            },
            cancellationToken).ConfigureAwait(false);
        ApplyPlaybackConfiguration(configuration, response.Playback);
        _state.Set("online", heartbeat: true);
    }

    private static void ApplyPlaybackConfiguration(
        PluginConfiguration configuration,
        ConnectorPlaybackConfiguration? playback)
    {
        var relayUrl = playback?.RelayWebSocketUrl?.Trim() ?? string.Empty;
        var playbackEnabled = playback?.Enabled == true
            && Uri.TryCreate(relayUrl, UriKind.Absolute, out var relayUri)
            && relayUri.Scheme == "wss";
        if (configuration.RemotePlaybackEnabled == playbackEnabled
            && string.Equals(configuration.RelayWebSocketUrl, playbackEnabled ? relayUrl : string.Empty, StringComparison.Ordinal))
        {
            return;
        }

        configuration.RemotePlaybackEnabled = playbackEnabled;
        configuration.RelayWebSocketUrl = playbackEnabled ? relayUrl : string.Empty;
        KaevoPlugin.Instance?.SaveConfiguration();
    }

    private async Task HandleClaimAsync(
        PluginConfiguration configuration,
        KaevoConnectorSecrets secrets,
        CloudRequest request,
        CancellationToken cancellationToken)
    {
        try
        {
            var result = request.Method == "GET"
                ? await ExecuteReadAsync(configuration, secrets, request, cancellationToken).ConfigureAwait(false)
                : await ExecuteCommandAsync(configuration, secrets, request, cancellationToken).ConfigureAwait(false);
            await SendCloudAsync<JsonElement>(
                configuration,
                secrets,
                HttpMethod.Post,
                $"/v1/remote-requests/{Uri.EscapeDataString(request.RequestId)}/complete",
                new { connector_id = configuration.ConnectorId, http_status = result.Status, response = result.Payload, truncated = result.Truncated },
                cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            await SendCloudAsync<JsonElement>(
                configuration,
                secrets,
                HttpMethod.Post,
                $"/v1/remote-requests/{Uri.EscapeDataString(request.RequestId)}/fail",
                new { connector_id = configuration.ConnectorId, message = SanitizeError(exception), details = new { } },
                cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task<CommandResult> ExecuteReadAsync(
        PluginConfiguration configuration,
        KaevoConnectorSecrets secrets,
        CloudRequest request,
        CancellationToken cancellationToken)
    {
        if (!configuration.RemoteMetadataEnabled || request.Provider != "jellyfin")
        {
            throw new InvalidOperationException("remoteMetadataDisabled");
        }

        if (request.Path == "/kaevo/internal/image")
        {
            if (!configuration.RemoteArtworkEnabled)
            {
                throw new InvalidOperationException("remoteArtworkDisabled");
            }

            return await ReadArtworkAsync(configuration, secrets, request.Query, cancellationToken).ConfigureAwait(false);
        }

        if (request.Path == "/kaevo/internal/main-snapshot")
        {
            return await ReadMainSnapshotAsync(configuration, secrets, request.Query, cancellationToken).ConfigureAwait(false);
        }

        if (!IsAllowedMetadataPath(request.Path) || HasUnsafeQuery(request.Query))
        {
            throw new InvalidOperationException("remoteMetadataRouteNotAllowed");
        }

        return await SendLocalAsync(configuration, secrets, HttpMethod.Get, request.Path, request.Query, null, cancellationToken)
            .ConfigureAwait(false);
    }

    private async Task<CommandResult> ExecuteCommandAsync(
        PluginConfiguration configuration,
        KaevoConnectorSecrets secrets,
        CloudRequest request,
        CancellationToken cancellationToken)
    {
        var operation = request.Operation ?? request.Path.Replace("/commands/", string.Empty, StringComparison.Ordinal);
        var parameters = request.Parameters ?? new Dictionary<string, JsonElement>();
        if (operation == "optimizer.scan")
        {
            if (!configuration.MediaScanEnabled)
            {
                throw new InvalidOperationException("mediaScanDisabled");
            }

            return new CommandResult(200, JsonSerializer.SerializeToElement(new
            {
                requestId = request.RequestId,
                state = "complete",
                operation,
                result = new
                {
                    libraries = _libraryManager.GetVirtualFolders().Count,
                    bounded = true,
                    read_only = true,
                    optimizer_execution_enabled = false
                }
            }, JsonOptions), false);
        }

        if (operation == "optimizer.plan_remux")
        {
            if (!configuration.OptimizerPlanningEnabled)
            {
                throw new InvalidOperationException("optimizerPlanningDisabled");
            }

            var itemId = RequireItemId(parameters);
            return new CommandResult(200, JsonSerializer.SerializeToElement(new
            {
                requestId = request.RequestId,
                state = "complete",
                operation,
                result = new { item_id = itemId, eligible = false, reason = "mediaProbeNotImplemented", execution_enabled = false }
            }, JsonOptions), false);
        }

        if (operation == "optimizer.execute_remux")
        {
            throw new InvalidOperationException("optimizerExecutionDisabled");
        }

        if (operation == "jellyfin.prepare_playback")
        {
            if (!configuration.RemotePlaybackEnabled)
            {
                throw new InvalidOperationException("remotePlaybackDisabled");
            }

            return await PreparePlaybackAsync(configuration, secrets, request, parameters, cancellationToken).ConfigureAwait(false);
        }

        if (operation is "jellyfin.mark_played" or "jellyfin.mark_unplayed" or "jellyfin.favorite" or "jellyfin.unfavorite")
        {
            if (!configuration.RemoteWritesEnabled)
            {
                throw new InvalidOperationException("remoteWritesDisabled");
            }

            var itemId = RequireItemId(parameters);
            var (method, suffix) = operation switch
            {
                "jellyfin.mark_played" => (HttpMethod.Post, "UserPlayedItems"),
                "jellyfin.mark_unplayed" => (HttpMethod.Delete, "UserPlayedItems"),
                "jellyfin.favorite" => (HttpMethod.Post, "UserFavoriteItems"),
                _ => (HttpMethod.Delete, "UserFavoriteItems")
            };
            var path = $"/{suffix}/{itemId}?userId={Uri.EscapeDataString(configuration.JellyfinUserId)}";
            await SendLocalAsync(configuration, secrets, method, path, null, null, cancellationToken).ConfigureAwait(false);
            return new CommandResult(200, JsonSerializer.SerializeToElement(new
            {
                requestId = request.RequestId,
                state = "complete",
                operation,
                result = new { item_id = itemId, applied = true }
            }, JsonOptions), false);
        }

        throw new InvalidOperationException("remoteCommandNotAllowed");
    }

    private async Task<CommandResult> PreparePlaybackAsync(
        PluginConfiguration configuration,
        KaevoConnectorSecrets secrets,
        CloudRequest request,
        IReadOnlyDictionary<string, JsonElement> parameters,
        CancellationToken cancellationToken)
    {
        var itemId = RequireItemId(parameters);
        var deviceId = parameters.TryGetValue("device_id", out var device) ? device.GetString() ?? string.Empty : string.Empty;
        if (!SafeIdentifierRegex().IsMatch(deviceId))
        {
            throw new InvalidOperationException("playbackDeviceInvalid");
        }

        var maxBitrate = parameters.TryGetValue("max_bitrate", out var bitrate) && bitrate.TryGetInt32(out var supplied)
            ? Math.Clamp(supplied, 1_000_000, configuration.MaximumPlaybackBitrate)
            : configuration.MaximumPlaybackBitrate;
        var body = new
        {
            UserId = configuration.JellyfinUserId,
            MaxStreamingBitrate = maxBitrate,
            EnableDirectPlay = true,
            EnableDirectStream = true,
            EnableTranscoding = true,
            AllowVideoStreamCopy = true,
            AllowAudioStreamCopy = true,
            DeviceProfile = new
            {
                Name = "Kaevo Apple HLS",
                MaxStreamingBitrate = maxBitrate,
                DirectPlayProfiles = new[]
                {
                    new { Container = "mp4,m4v,mov", Type = "Video", VideoCodec = "h264,hevc", AudioCodec = "aac,ac3,eac3" }
                },
                TranscodingProfiles = new[]
                {
                    new { Container = "ts", Type = "Video", VideoCodec = "h264", AudioCodec = "aac", Protocol = "hls", Context = "Streaming" }
                }
            }
        };
        var local = await SendLocalAsync(
            configuration,
            secrets,
            HttpMethod.Post,
            $"/Items/{itemId}/PlaybackInfo?UserId={Uri.EscapeDataString(configuration.JellyfinUserId)}",
            null,
            body,
            cancellationToken).ConfigureAwait(false);
        var root = local.Payload;
        var source = root.TryGetProperty("MediaSources", out var sources) && sources.ValueKind == JsonValueKind.Array
            ? sources.EnumerateArray().FirstOrDefault()
            : default;
        if (source.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidOperationException("playbackSourceUnavailable");
        }

        var mediaSourceId = source.TryGetProperty("Id", out var sourceId) ? sourceId.GetString() : null;
        var playSessionId = root.TryGetProperty("PlaySessionId", out var sessionId) ? sessionId.GetString() : null;
        if (string.IsNullOrWhiteSpace(mediaSourceId) || string.IsNullOrWhiteSpace(playSessionId))
        {
            throw new InvalidOperationException("playbackIdentifiersMissing");
        }

        var direct = source.TryGetProperty("SupportsDirectPlay", out var directValue) && directValue.GetBoolean();
        var remux = source.TryGetProperty("SupportsDirectStream", out var streamValue) && streamValue.GetBoolean();
        var mode = direct ? "direct_play" : remux ? "remux" : "transcode";
        return new CommandResult(200, JsonSerializer.SerializeToElement(new
        {
            requestId = request.RequestId,
            state = "complete",
            operation = "jellyfin.prepare_playback",
            result = new
            {
                item_id = itemId,
                media_source_id = mediaSourceId,
                playback_session_id = playSessionId,
                mode,
                max_bitrate = maxBitrate
            }
        }, JsonOptions), false);
    }

    private async Task<CommandResult> ReadArtworkAsync(
        PluginConfiguration configuration,
        KaevoConnectorSecrets secrets,
        IReadOnlyDictionary<string, JsonElement>? query,
        CancellationToken cancellationToken)
    {
        var itemId = QueryString(query, "item_id");
        var imageType = QueryString(query, "image_type");
        if (!ItemIdRegex().IsMatch(itemId) || imageType is not ("Primary" or "Backdrop" or "Logo" or "Thumb"))
        {
            throw new InvalidOperationException("remoteArtworkRequestInvalid");
        }

        var requestedWidth = Math.Clamp(QueryInt(query, "max_width", 600), 1, RemoteArtworkMaximumDimension);
        var requestedHeight = Math.Clamp(QueryInt(query, "max_height", 900), 1, RemoteArtworkMaximumDimension);
        var requestedQuality = Math.Clamp(QueryInt(query, "quality", 90), 1, 95);
        var attempts = new[]
        {
            (Width: requestedWidth, Height: requestedHeight, Quality: requestedQuality),
            (Width: Math.Min(requestedWidth, 1920), Height: Math.Min(requestedHeight, 1920), Quality: Math.Min(requestedQuality, 88)),
            (Width: Math.Min(requestedWidth, 1600), Height: Math.Min(requestedHeight, 1600), Quality: Math.Min(requestedQuality, 85)),
            (Width: Math.Min(requestedWidth, 1440), Height: Math.Min(requestedHeight, 1440), Quality: Math.Min(requestedQuality, 82)),
            (Width: Math.Min(requestedWidth, 1200), Height: Math.Min(requestedHeight, 1200), Quality: Math.Min(requestedQuality, 80))
        }.Distinct();

        foreach (var attempt in attempts)
        {
            var parameters = new Dictionary<string, JsonElement>
            {
                ["maxWidth"] = JsonSerializer.SerializeToElement(attempt.Width),
                ["maxHeight"] = JsonSerializer.SerializeToElement(attempt.Height),
                ["quality"] = JsonSerializer.SerializeToElement(attempt.Quality)
            };
            var uri = BuildLocalUri(configuration, $"/Items/{itemId}/Images/{imageType}", parameters);
            using var message = new HttpRequestMessage(HttpMethod.Get, uri);
            message.Headers.Add("X-Emby-Token", secrets.JellyfinApiKey);
            message.Headers.Accept.ParseAdd("image/jpeg,image/png,image/webp");
            using var response = await _jellyfin.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();
            var contentType = response.Content.Headers.ContentType?.MediaType?.ToLowerInvariant() ?? string.Empty;
            if (contentType is not ("image/jpeg" or "image/png" or "image/webp"))
            {
                throw new InvalidOperationException("remoteArtworkContentTypeInvalid");
            }

            var bytes = await ReadBoundedAsync(response.Content, RemoteArtworkMaximumBytes, cancellationToken).ConfigureAwait(false);
            if (bytes.Truncated)
            {
                continue;
            }

            return new CommandResult(200, JsonSerializer.SerializeToElement(new
            {
                content_type = contentType,
                body_base64 = Convert.ToBase64String(bytes.Data)
            }, JsonOptions), false);
        }

        throw new InvalidOperationException("remoteArtworkPayloadTooLarge");
    }

    private async Task<CommandResult> ReadMainSnapshotAsync(
        PluginConfiguration configuration,
        KaevoConnectorSecrets secrets,
        IReadOnlyDictionary<string, JsonElement>? query,
        CancellationToken cancellationToken)
    {
        var userId = QueryString(query, "userId");
        if (string.IsNullOrWhiteSpace(userId))
        {
            userId = configuration.JellyfinUserId;
        }

        if (!ItemIdRegex().IsMatch(userId))
        {
            throw new InvalidOperationException("snapshotUserInvalid");
        }

        var moviesLimit = Math.Clamp(QueryInt(query, "moviesLimit", 80), 1, 80);
        var showsLimit = Math.Clamp(QueryInt(query, "showsLimit", 80), 1, 80);
        var collectionsLimit = Math.Clamp(QueryInt(query, "collectionsLimit", 50), 1, 50);
        var resumeLimit = Math.Clamp(QueryInt(query, "resumeLimit", 20), 1, 20);
        var viewsTask = SendLocalAsync(configuration, secrets, HttpMethod.Get, $"/Users/{userId}/Views", null, null, cancellationToken);
        var moviesTask = ReadSnapshotItemsAsync(configuration, secrets, userId, "Movie", moviesLimit, null, cancellationToken);
        var showsTask = ReadSnapshotItemsAsync(configuration, secrets, userId, "Series", showsLimit, null, cancellationToken);
        var collectionsTask = ReadSnapshotItemsAsync(configuration, secrets, userId, "BoxSet", collectionsLimit, null, cancellationToken);
        var resumeTask = ReadSnapshotItemsAsync(configuration, secrets, userId, "Movie,Episode", resumeLimit, true, cancellationToken);
        await Task.WhenAll(viewsTask, moviesTask, showsTask, collectionsTask, resumeTask).ConfigureAwait(false);
        return new CommandResult(200, JsonSerializer.SerializeToElement(new
        {
            version = "0.2.4",
            generated_at = DateTimeOffset.UtcNow,
            views = viewsTask.Result.Payload,
            movies = moviesTask.Result.Payload,
            shows = showsTask.Result.Payload,
            collections = collectionsTask.Result.Payload,
            continueWatching = resumeTask.Result.Payload,
            limits = new { movies_limit = moviesLimit, shows_limit = showsLimit, collections_limit = collectionsLimit, resume_limit = resumeLimit }
        }, JsonOptions), false);
    }

    private Task<CommandResult> ReadSnapshotItemsAsync(
        PluginConfiguration configuration,
        KaevoConnectorSecrets secrets,
        string userId,
        string includeItemTypes,
        int limit,
        bool? isResumable,
        CancellationToken cancellationToken)
    {
        var query = new Dictionary<string, JsonElement>
        {
            ["Recursive"] = JsonSerializer.SerializeToElement(true),
            ["StartIndex"] = JsonSerializer.SerializeToElement(0),
            ["Limit"] = JsonSerializer.SerializeToElement(limit),
            ["IncludeItemTypes"] = JsonSerializer.SerializeToElement(includeItemTypes),
            ["Fields"] = JsonSerializer.SerializeToElement("Overview,Genres,Studios,People,MediaSources,MediaStreams,ProviderIds,PrimaryImageAspectRatio"),
            ["EnableUserData"] = JsonSerializer.SerializeToElement(true),
            ["EnableImages"] = JsonSerializer.SerializeToElement(true),
            ["ImageTypeLimit"] = JsonSerializer.SerializeToElement(1),
            ["SortBy"] = JsonSerializer.SerializeToElement(isResumable == true ? "DatePlayed" : "SortName"),
            ["SortOrder"] = JsonSerializer.SerializeToElement(isResumable == true ? "Descending" : "Ascending")
        };
        if (isResumable is not null)
        {
            query["IsResumable"] = JsonSerializer.SerializeToElement(isResumable.Value);
        }

        return SendLocalAsync(configuration, secrets, HttpMethod.Get, $"/Users/{userId}/Items", query, null, cancellationToken);
    }

    private async Task<CommandResult> SendLocalAsync(
        PluginConfiguration configuration,
        KaevoConnectorSecrets secrets,
        HttpMethod method,
        string path,
        IReadOnlyDictionary<string, JsonElement>? query,
        object? body,
        CancellationToken cancellationToken)
    {
        var uri = BuildLocalUri(configuration, path, query);
        using var message = new HttpRequestMessage(method, uri);
        message.Headers.Add("X-Emby-Token", secrets.JellyfinApiKey);
        message.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        if (body is not null)
        {
            message.Content = new StringContent(JsonSerializer.Serialize(body, JsonOptions), Encoding.UTF8, "application/json");
        }

        using var response = await _jellyfin.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        var bounded = await ReadBoundedAsync(response.Content, configuration.MaximumRemoteResponseBytes, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException($"jellyfinHttp{(int)response.StatusCode}");
        }

        var payload = bounded.Data.Length == 0
            ? JsonSerializer.SerializeToElement(new { state = "ok" }, JsonOptions)
            : JsonSerializer.Deserialize<JsonElement>(bounded.Data, JsonOptions);
        return new CommandResult((int)response.StatusCode, payload, bounded.Truncated);
    }

    private async Task RunRelayLoopAsync(
        PluginConfiguration configuration,
        KaevoConnectorSecrets secrets,
        CancellationToken cancellationToken)
    {
        var relayTicket = await SendCloudAsync<RelayTicketResponse>(
            configuration,
            secrets,
            HttpMethod.Post,
            $"/v1/home-connectors/{Uri.EscapeDataString(configuration.ConnectorId)}/relay-ticket",
            new { },
            cancellationToken).ConfigureAwait(false);
        using var socket = new ClientWebSocket();
        socket.Options.KeepAliveInterval = TimeSpan.FromSeconds(20);
        socket.Options.SetRequestHeader("Authorization", $"Bearer {relayTicket.RelayTicket}");
        var relayUri = new Uri($"{configuration.RelayWebSocketUrl.TrimEnd('/')}/v1/connectors/{Uri.EscapeDataString(configuration.ConnectorId)}");
        await socket.ConnectAsync(relayUri, cancellationToken).ConfigureAwait(false);
        var sendGate = new SemaphoreSlim(1, 1);
        var active = new Dictionary<string, CancellationTokenSource>(StringComparer.Ordinal);
        while (socket.State == WebSocketState.Open && !cancellationToken.IsCancellationRequested)
        {
            var raw = await ReceiveTextAsync(socket, cancellationToken).ConfigureAwait(false);
            var message = JsonSerializer.Deserialize<RelayMessage>(raw, JsonOptions)
                ?? throw new InvalidOperationException("relayMessageMalformed");
            if (message.Type == "ping")
            {
                await SendTextAsync(
                    socket,
                    sendGate,
                    JsonSerializer.Serialize(new { type = "pong" }, JsonOptions),
                    cancellationToken).ConfigureAwait(false);
            }
            else if (message.Type == "cancel" && active.Remove(message.RequestId, out var existing))
            {
                existing.Cancel();
                existing.Dispose();
            }
            else if (message.Type == "request" && !string.IsNullOrWhiteSpace(message.Grant))
            {
                var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                active[message.RequestId] = linked;
                _ = HandleRelayRequestAsync(configuration, secrets, socket, sendGate, message, linked.Token)
                    .ContinueWith(_ =>
                    {
                        if (active.Remove(message.RequestId, out var completed))
                        {
                            completed.Dispose();
                        }
                    }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            }
        }
    }

    private async Task RunRelaySupervisorAsync(
        PluginConfiguration configuration,
        KaevoConnectorSecrets secrets,
        CancellationToken cancellationToken)
    {
        var delay = TimeSpan.FromSeconds(1);
        while (!cancellationToken.IsCancellationRequested && configuration.RemotePlaybackEnabled)
        {
            try
            {
                await RunRelayLoopAsync(configuration, secrets, cancellationToken).ConfigureAwait(false);
                delay = TimeSpan.FromSeconds(1);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception)
            {
                _logger.LogWarning(
                    "Kaevo playback relay reconnecting: {Category}",
                    SanitizeError(exception));
                await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
                delay = TimeSpan.FromSeconds(Math.Min(delay.TotalSeconds * 2, 30));
            }
        }
    }

    private async Task HandleRelayRequestAsync(
        PluginConfiguration configuration,
        KaevoConnectorSecrets secrets,
        ClientWebSocket socket,
        SemaphoreSlim sendGate,
        RelayMessage message,
        CancellationToken cancellationToken)
    {
        try
        {
            var grant = KaevoPlaybackSecurity.VerifyGrant(message.Grant!, secrets.PlaybackGrantKey, configuration.ConnectorId);
            var resolved = KaevoPlaybackSecurity.Resolve(grant, message.Method ?? "GET", message.Path ?? string.Empty, message.Query, message.Range);
            using var local = new HttpRequestMessage(resolved.Method, BuildLocalUri(configuration, resolved.PathAndQuery, null));
            local.Headers.Add("X-Emby-Token", secrets.JellyfinApiKey);
            if (!string.IsNullOrWhiteSpace(resolved.RangeHeader))
            {
                local.Headers.TryAddWithoutValidation("Range", resolved.RangeHeader);
            }

            using var response = await _jellyfin.SendAsync(local, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
            var safeHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var header in response.Content.Headers.Concat(response.Headers))
            {
                if (header.Key is "Content-Type" or "Content-Length" or "Content-Range" or "Accept-Ranges" or "Cache-Control")
                {
                    safeHeaders[header.Key.ToLowerInvariant()] = string.Join(',', header.Value);
                }
            }

            var isPlaylist = resolved.PathAndQuery.Contains(".m3u8", StringComparison.OrdinalIgnoreCase);
            if (isPlaylist)
            {
                safeHeaders.Remove("content-length");
            }

            await SendTextAsync(socket, sendGate, JsonSerializer.Serialize(new
            {
                type = "response_start",
                request_id = message.RequestId,
                status = (int)response.StatusCode,
                headers = safeHeaders
            }, JsonOptions), cancellationToken).ConfigureAwait(false);

            if (isPlaylist)
            {
                var playlist = await ReadBoundedAsync(response.Content, 1_048_576, cancellationToken).ConfigureAwait(false);
                if (playlist.Truncated)
                {
                    throw new InvalidOperationException("playlistTooLarge");
                }

                var prefixPath = $"/v1/playback/{message.Grant}";
                var rewritten = string.Join('\n', Encoding.UTF8.GetString(playlist.Data)
                    .Split('\n')
                    .Select(line => line.StartsWith("/Videos/", StringComparison.Ordinal) ? prefixPath + line : line));
                var prefix = Encoding.ASCII.GetBytes(message.RequestId);
                var body = Encoding.UTF8.GetBytes(rewritten);
                var payload = new byte[prefix.Length + body.Length];
                prefix.CopyTo(payload, 0);
                body.CopyTo(payload, prefix.Length);
                await SendBinaryAsync(socket, sendGate, payload, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
                var buffer = new byte[256 * 1024];
                while (true)
                {
                    var count = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                    if (count == 0)
                    {
                        break;
                    }

                    var prefix = Encoding.ASCII.GetBytes(message.RequestId);
                    var payload = new byte[prefix.Length + count];
                    prefix.CopyTo(payload, 0);
                    buffer.AsSpan(0, count).CopyTo(payload.AsSpan(prefix.Length));
                    await SendBinaryAsync(socket, sendGate, payload, cancellationToken).ConfigureAwait(false);
                }
            }

            await SendTextAsync(socket, sendGate, JsonSerializer.Serialize(new { type = "response_end", request_id = message.RequestId }, JsonOptions), cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception exception)
        {
            await SendTextAsync(socket, sendGate, JsonSerializer.Serialize(new
            {
                type = "error",
                request_id = message.RequestId,
                category = SanitizeError(exception)
            }, JsonOptions), CancellationToken.None).ConfigureAwait(false);
        }
    }

    private async Task<T> SendCloudAsync<T>(
        PluginConfiguration configuration,
        KaevoConnectorSecrets? secrets,
        HttpMethod method,
        string path,
        object body,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, new Uri(new Uri(configuration.CloudBaseUrl.TrimEnd('/') + "/"), path.TrimStart('/')))
        {
            Content = new StringContent(JsonSerializer.Serialize(body, JsonOptions), Encoding.UTF8, "application/json")
        };
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        if (secrets is not null)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", secrets.ConnectorToken);
        }

        using var response = await _cloud.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException($"cloudHttp{(int)response.StatusCode}");
        }

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        return await JsonSerializer.DeserializeAsync<T>(stream, JsonOptions, cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidOperationException("cloudResponseMalformed");
    }

    private static PluginConfiguration CurrentConfiguration()
        => KaevoPlugin.Instance?.Configuration ?? throw new InvalidOperationException("pluginConfigurationUnavailable");

    private static void ValidateConfiguration(PluginConfiguration configuration)
    {
        if (!Uri.TryCreate(configuration.CloudBaseUrl, UriKind.Absolute, out var cloud) || cloud.Scheme != Uri.UriSchemeHttps)
        {
            throw new InvalidOperationException("cloudBaseUrlInvalid");
        }

        if (!Uri.TryCreate(configuration.LocalJellyfinBaseUrl, UriKind.Absolute, out var local)
            || !IPAddress.TryParse(local.Host, out var address)
            || !IPAddress.IsLoopback(address))
        {
            throw new InvalidOperationException("localJellyfinMustUseLoopback");
        }

        if (configuration.RemotePlaybackEnabled
            && (!Uri.TryCreate(configuration.RelayWebSocketUrl, UriKind.Absolute, out var relay) || relay.Scheme != "wss"))
        {
            throw new InvalidOperationException("relayWebSocketUrlInvalid");
        }

        if (string.IsNullOrWhiteSpace(configuration.ProfileId))
        {
            throw new InvalidOperationException("cloudProfileMissing");
        }
    }

    private static Uri BuildLocalUri(
        PluginConfiguration configuration,
        string path,
        IReadOnlyDictionary<string, JsonElement>? query)
    {
        var baseUri = new Uri(configuration.LocalJellyfinBaseUrl.TrimEnd('/') + "/");
        var uri = new Uri(baseUri, path.TrimStart('/'));
        if (query is null || query.Count == 0 || path.Contains('?', StringComparison.Ordinal))
        {
            return uri;
        }

        var builder = new UriBuilder(uri)
        {
            Query = string.Join('&', query.Select(pair =>
                $"{Uri.EscapeDataString(pair.Key)}={Uri.EscapeDataString(pair.Value.ValueKind == JsonValueKind.String ? pair.Value.GetString() ?? string.Empty : pair.Value.ToString())}"))
        };
        return builder.Uri;
    }

    private static bool IsAllowedMetadataPath(string path)
        => path == "/System/Info"
            || UserViewsRegex().IsMatch(path)
            || UserItemsRegex().IsMatch(path)
            || ShowRouteRegex().IsMatch(path);

    private static bool HasUnsafeQuery(IReadOnlyDictionary<string, JsonElement>? query)
        => query is not null && query.Keys.Any(key => !SafeMetadataQuery.Contains(key));

    private static string RequireItemId(IReadOnlyDictionary<string, JsonElement> parameters)
    {
        var value = parameters.TryGetValue("item_id", out var item) ? item.GetString() ?? string.Empty : string.Empty;
        if (!ItemIdRegex().IsMatch(value))
        {
            throw new InvalidOperationException("jellyfinItemIdInvalid");
        }

        return value.ToLowerInvariant();
    }

    private static string QueryString(IReadOnlyDictionary<string, JsonElement>? query, string key)
        => query is not null && query.TryGetValue(key, out var value)
            ? value.ValueKind == JsonValueKind.String ? value.GetString() ?? string.Empty : value.ToString()
            : string.Empty;

    private static int QueryInt(IReadOnlyDictionary<string, JsonElement>? query, string key, int fallback)
        => int.TryParse(QueryString(query, key), out var value) ? value : fallback;

    private static async Task<(byte[] Data, bool Truncated)> ReadBoundedAsync(
        HttpContent content,
        int maximum,
        CancellationToken cancellationToken)
    {
        await using var input = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        await using var output = new MemoryStream();
        var buffer = new byte[64 * 1024];
        var truncated = false;
        while (true)
        {
            var count = await input.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (count == 0)
            {
                break;
            }

            var remaining = maximum - checked((int)output.Length);
            if (remaining <= 0)
            {
                truncated = true;
                break;
            }

            await output.WriteAsync(buffer.AsMemory(0, Math.Min(count, remaining)), cancellationToken).ConfigureAwait(false);
            if (count > remaining)
            {
                truncated = true;
                break;
            }
        }

        return (output.ToArray(), truncated);
    }

    private static async Task<string> ReceiveTextAsync(ClientWebSocket socket, CancellationToken cancellationToken)
    {
        var buffer = new byte[64 * 1024];
        await using var output = new MemoryStream();
        WebSocketReceiveResult result;
        do
        {
            result = await socket.ReceiveAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (result.MessageType == WebSocketMessageType.Close)
            {
                throw new InvalidOperationException("relayDisconnected");
            }

            if (result.MessageType != WebSocketMessageType.Text || output.Length + result.Count > 1_048_576)
            {
                throw new InvalidOperationException("relayMessageInvalid");
            }

            await output.WriteAsync(buffer.AsMemory(0, result.Count), cancellationToken).ConfigureAwait(false);
        }
        while (!result.EndOfMessage);
        return Encoding.UTF8.GetString(output.ToArray());
    }

    private static async Task SendTextAsync(ClientWebSocket socket, SemaphoreSlim gate, string value, CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var bytes = Encoding.UTF8.GetBytes(value);
            await socket.SendAsync(bytes, WebSocketMessageType.Text, true, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            gate.Release();
        }
    }

    private static async Task SendBinaryAsync(ClientWebSocket socket, SemaphoreSlim gate, byte[] value, CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await socket.SendAsync(value, WebSocketMessageType.Binary, true, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            gate.Release();
        }
    }

    private static async Task IgnoreCancellation(Task task)
    {
        try
        {
            await task.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }
    }

    private static string SanitizeError(Exception exception)
        => exception is InvalidOperationException && SafeErrorRegex().IsMatch(exception.Message)
            ? exception.Message
            : "connectorOperationFailed";

    private static ProviderReachability ProviderStatus(bool ok, bool configured, string version, string? reason)
        => new(ok, configured, version, reason);

    private sealed record CommandResult(int Status, JsonElement Payload, bool Truncated);
    private sealed record ProviderReachability(bool Ok, bool Configured, string Version, string? Reason);

    [GeneratedRegex("^[0-9a-fA-F]{32}$", RegexOptions.CultureInvariant)]
    private static partial Regex ItemIdRegex();

    [GeneratedRegex("^[A-Za-z0-9._:-]{1,128}$", RegexOptions.CultureInvariant)]
    private static partial Regex SafeIdentifierRegex();

    [GeneratedRegex("^/Users/[0-9a-fA-F]{32}/Views$", RegexOptions.CultureInvariant)]
    private static partial Regex UserViewsRegex();

    [GeneratedRegex("^/Users/[0-9a-fA-F]{32}/Items(?:/[0-9a-fA-F]{32})?(?:/Resume)?$", RegexOptions.CultureInvariant)]
    private static partial Regex UserItemsRegex();

    [GeneratedRegex("^/Shows/[0-9a-fA-F]{32}/(Seasons|Episodes)$", RegexOptions.CultureInvariant)]
    private static partial Regex ShowRouteRegex();

    [GeneratedRegex("^[A-Za-z][A-Za-z0-9]{2,80}$", RegexOptions.CultureInvariant)]
    private static partial Regex SafeErrorRegex();
}
