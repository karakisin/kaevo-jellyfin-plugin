using System.Collections.Concurrent;
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
    private const int RemoteArtworkMaximumBytes = 3_500_000;
    private const int RemoteArtworkMaximumDimension = 2_160;
    private const int RelayChannelCount = 3;
    private const int ControlRequestConcurrency = 4;
    private static readonly HashSet<string> SupportedLocalProviders = new(StringComparer.OrdinalIgnoreCase)
    {
        "sonarr", "radarr", "seerr", "lidarr", "readarr", "prowlarr", "bazarr", "tdarr"
    };
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
    private readonly KaevoOptimizerCoordinator _optimizer;
    private readonly ILogger<KaevoCloudConnectorService> _logger;
    private readonly KaevoProviderTransport _providerTransport;
    private readonly KaevoConnectorLifecycleStore _lifecycleStore;
    private readonly KaevoConnectorLifecycleClient _lifecycleClient;
    private readonly HttpClient _jellyfin = new() { Timeout = TimeSpan.FromSeconds(45) };

    public KaevoCloudConnectorService(
        KaevoSecretStore secretStore,
        KaevoCloudState state,
        ILibraryManager libraryManager,
        KaevoOptimizerCoordinator optimizer,
        KaevoProviderTransport providerTransport,
        KaevoConnectorLifecycleStore lifecycleStore,
        KaevoConnectorLifecycleClient lifecycleClient,
        ILogger<KaevoCloudConnectorService> logger)
    {
        _secretStore = secretStore;
        _state = state;
        _libraryManager = libraryManager;
        _optimizer = optimizer;
        _providerTransport = providerTransport;
        _lifecycleStore = lifecycleStore;
        _lifecycleClient = lifecycleClient;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var delay = TimeSpan.FromSeconds(1);
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var configurationChanged = _state.ConfigurationChangedToken();
                var configuration = CurrentConfiguration();
                if (!configuration.CloudConnectorEnabled)
                {
                    _state.Set("disabled");
                    _state.SetRelay("disabled");
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
                using var linked = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken, configurationChanged);
                var control = RunControlSupervisorAsync(configuration, secrets, linked.Token);
                var relay = configuration.RemotePlaybackEnabled
                    ? RunRelayPoolAsync(configuration, secrets, linked.Token)
                    : Task.Delay(Timeout.Infinite, linked.Token);
                if (!configuration.RemotePlaybackEnabled)
                {
                    _state.SetRelay("disabled");
                }
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

    private async Task RunControlSupervisorAsync(
        PluginConfiguration configuration,
        KaevoConnectorSecrets secrets,
        CancellationToken cancellationToken)
    {
        var delay = TimeSpan.FromSeconds(1);
        var registered = true;
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                if (!registered)
                {
                    await RegisterAsync(configuration, secrets, cancellationToken).ConfigureAwait(false);
                    registered = true;
                }

                await RunControlLoopAsync(configuration, secrets, cancellationToken).ConfigureAwait(false);
                delay = TimeSpan.FromSeconds(1);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception)
            {
                var category = SanitizeError(exception);
                registered = false;
                _state.Set("connecting", category);
                _logger.LogWarning("Kaevo Cloud control reconnecting: {Category}", category);
                await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
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
        if (existing is not null && !string.IsNullOrWhiteSpace(existing.ConnectorToken))
        {
            throw new InvalidOperationException("lifecycle_upgrade_required");
        }
        var lifecycle = await _lifecycleStore.LoadOrInitializeAsync(cancellationToken).ConfigureAwait(false);
        if (!string.IsNullOrEmpty(lifecycle.PendingKeyFile))
        {
            lifecycle = await _lifecycleClient.ReconcilePendingAsync(
                new Uri(configuration.CloudBaseUrl, UriKind.Absolute), configuration.ProfileId, cancellationToken).ConfigureAwait(false);
        }
        if (lifecycle.State != "active" || lifecycle.CredentialVersion < 1 || string.IsNullOrWhiteSpace(lifecycle.ConnectorId))
        {
            throw new InvalidOperationException("lifecycle_upgrade_required");
        }
        configuration.ConnectorId = lifecycle.ConnectorId;
        configuration.PairingCode = string.Empty;
        configuration.RemotePlaybackEnabled = false;
        var secrets = existing is null
            ? new KaevoConnectorSecrets(string.Empty, string.Empty, jellyfinCredential)
            : existing with { ConnectorToken = string.Empty, PlaybackGrantKey = string.Empty, JellyfinApiKey = jellyfinCredential };
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
                app_version = "0.2.49",
                capabilities = new[]
                {
                    "remote_metadata_v1", "remote_artwork_v1", "remote_commands_v1",
                    "playback_tunnel_v1", "direct_play", "hls_remux", "hls_transcode",
                    "bounded_media_scan_v1", "optimizer_plan_v1", "sonarr_episode_management_v1",
                    "local_provider_configuration_v1"
                },
                provider_status = BuildProviderStatus(secrets, configuration, includeOptimizer: false)
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
        var inFlight = new List<Task>(ControlRequestConcurrency);
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                for (var index = inFlight.Count - 1; index >= 0; index--)
                {
                    if (!inFlight[index].IsCompleted)
                    {
                        continue;
                    }

                    await inFlight[index].ConfigureAwait(false);
                    inFlight.RemoveAt(index);
                }

                if (DateTimeOffset.UtcNow >= heartbeatAt)
                {
                    await HeartbeatAsync(configuration, secrets, cancellationToken).ConfigureAwait(false);
                    heartbeatAt = DateTimeOffset.UtcNow.AddSeconds(60);
                }

                if (inFlight.Count >= ControlRequestConcurrency)
                {
                    await Task.WhenAny(inFlight).ConfigureAwait(false);
                    continue;
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
                    inFlight.Add(HandleClaimAsync(configuration, secrets, claim.Request, cancellationToken));
                    continue;
                }

                await Task.Delay(TimeSpan.FromMilliseconds(250), cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            await IgnoreCancellation(Task.WhenAll(inFlight)).ConfigureAwait(false);
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
                provider_status = BuildProviderStatus(secrets, configuration, includeOptimizer: true)
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
            // Provider settings can be saved while the long-running connector is
            // already online. Re-read the owner-only secret file for every claim
            // so health checks, searches, and mutations all use the same current
            // provider configuration without requiring a Jellyfin restart.
            var currentSecrets = await _secretStore.ReadAsync(cancellationToken).ConfigureAwait(false) ?? secrets;
            var result = request.Method == "GET"
                ? await ExecuteReadAsync(configuration, currentSecrets, request, cancellationToken).ConfigureAwait(false)
                : await ExecuteCommandAsync(configuration, currentSecrets, request, cancellationToken).ConfigureAwait(false);
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
        if (!configuration.RemoteMetadataEnabled)
        {
            throw new InvalidOperationException("remoteMetadataDisabled");
        }

        if (!string.Equals(request.Provider, "jellyfin", StringComparison.OrdinalIgnoreCase))
        {
            if (!SupportedLocalProviders.Contains(request.Provider)
                || !IsAllowedProviderReadPath(request.Provider, request.Path)
                || HasUnsafeProviderQuery(request.Query))
            {
                throw new InvalidOperationException("remoteProviderRouteNotAllowed");
            }

            return await SendProviderReadAsync(
                configuration,
                secrets,
                request.Provider,
                request.Path,
                request.Query,
                cancellationToken).ConfigureAwait(false);
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

            var limit = parameters.TryGetValue("limit", out var limitValue) && limitValue.TryGetInt32(out var requestedLimit)
                ? Math.Clamp(requestedLimit, 1, 100)
                : 50;
            var startIndex = parameters.TryGetValue("start_index", out var startValue) && startValue.TryGetInt32(out var requestedStart)
                ? Math.Clamp(requestedStart, 0, 1_000_000)
                : 0;
            var userId = configuration.JellyfinUserId;
            if (!ItemIdRegex().IsMatch(userId))
            {
                throw new InvalidOperationException("optimizerUserInvalid");
            }

            var query = new Dictionary<string, JsonElement>
            {
                ["Recursive"] = JsonSerializer.SerializeToElement(true),
                ["StartIndex"] = JsonSerializer.SerializeToElement(startIndex),
                ["Limit"] = JsonSerializer.SerializeToElement(limit),
                ["IncludeItemTypes"] = JsonSerializer.SerializeToElement("Movie,Episode"),
                ["Fields"] = JsonSerializer.SerializeToElement("MediaSources,MediaStreams"),
                ["EnableUserData"] = JsonSerializer.SerializeToElement(false),
                ["EnableImages"] = JsonSerializer.SerializeToElement(false)
            };
            var inventory = await SendLocalAsync(
                configuration,
                secrets,
                HttpMethod.Get,
                $"/Users/{userId}/Items",
                query,
                null,
                cancellationToken).ConfigureAwait(false);
            if (inventory.Truncated)
            {
                throw new InvalidOperationException("optimizerScanPayloadTooLarge");
            }

            return CompleteCommand(
                request,
                operation,
                KaevoPlaybackCompatibilityScanner.Scan(inventory.Payload, startIndex, limit));
        }

        if (operation == "optimizer.plan_remux")
        {
            var itemId = RequireItemId(parameters);
            var userId = configuration.JellyfinUserId;
            if (!ItemIdRegex().IsMatch(userId))
            {
                throw new InvalidOperationException("optimizerUserInvalid");
            }
            var query = new Dictionary<string, JsonElement>
            {
                ["Fields"] = JsonSerializer.SerializeToElement("MediaSources,MediaStreams"),
                ["EnableUserData"] = JsonSerializer.SerializeToElement(false),
                ["EnableImages"] = JsonSerializer.SerializeToElement(false)
            };
            var item = await SendLocalAsync(
                configuration,
                secrets,
                HttpMethod.Get,
                $"/Users/{userId}/Items/{itemId}",
                query,
                null,
                cancellationToken).ConfigureAwait(false);
            if (item.Truncated)
            {
                throw new InvalidOperationException("optimizerPlanPayloadTooLarge");
            }
            var conversion = KaevoPlaybackCompatibilityScanner.SelectConversion(item.Payload);
            if (parameters.TryGetValue("strategy", out var requestedStrategy)
                && requestedStrategy.ValueKind == JsonValueKind.String
                && requestedStrategy.GetString() == "full_video_conversion")
            {
                conversion = conversion with { Strategy = OptimizerConversionStrategy.FullVideo };
            }
            var repairAudioFromOriginal = parameters.TryGetValue("strategy", out requestedStrategy)
                && requestedStrategy.ValueKind == JsonValueKind.String
                && requestedStrategy.GetString() == "repair_audio_from_original";
            if (repairAudioFromOriginal)
            {
                conversion = conversion with { Strategy = OptimizerConversionStrategy.AudioOnly };
            }
            var plan = _optimizer.CreatePlan(
                itemId,
                KaevoPlaybackCompatibilityScanner.DisplayTitle(item.Payload),
                conversion.Strategy,
                conversion.VideoCodec,
                conversion.AudioCodec,
                repairAudioFromOriginal);
            return CompleteCommand(request, operation, KaevoPlaybackCompatibilityScanner.PlanDirectPlay(item.Payload, plan));
        }

        if (operation == "optimizer.execute_remux")
        {
            var planId = RequireGuid(parameters, "plan_id", "optimizerPlanInvalid");
            var approvalToken = RequireString(parameters, "approval_token", "optimizerApprovalInvalid");
            if (!parameters.TryGetValue("confirmation", out var confirmation)
                || confirmation.ValueKind != JsonValueKind.String
                || confirmation.GetString() != "YES_REMUX_ONE_FILE")
            {
                throw new InvalidOperationException("optimizerConfirmationRequired");
            }
            var job = _optimizer.Start(planId, approvalToken);
            return CompleteCommand(request, operation, OptimizerJobResult(job));
        }

        if (operation == "optimizer.job_status")
        {
            var jobId = RequireGuid(parameters, "job_id", "optimizerJobInvalid");
            return CompleteCommand(request, operation, OptimizerJobResult(_optimizer.Status(jobId)));
        }

        if (operation == "optimizer.jobs")
        {
            return CompleteCommand(request, operation, new { jobs = _optimizer.Jobs().Select(OptimizerJobResult).ToArray() });
        }

        if (operation == "optimizer.reorder_job")
        {
            var jobId = RequireGuid(parameters, "job_id", "optimizerJobInvalid");
            var priorityIndex = parameters.TryGetValue("priority_index", out var value) && value.TryGetInt32(out var supplied)
                ? Math.Clamp(supplied, 0, 10_000)
                : throw new InvalidOperationException("optimizerPriorityInvalid");
            return CompleteCommand(request, operation, OptimizerJobResult(_optimizer.Reorder(jobId, priorityIndex)));
        }

        if (operation == "optimizer.cancel_job")
        {
            var jobId = RequireGuid(parameters, "job_id", "optimizerJobInvalid");
            if (!parameters.TryGetValue("confirmation", out var confirmation)
                || confirmation.ValueKind != JsonValueKind.String
                || confirmation.GetString() != "YES_CANCEL_OPTIMIZATION")
            {
                throw new InvalidOperationException("optimizerCancellationConfirmationRequired");
            }
            return CompleteCommand(request, operation, OptimizerJobResult(_optimizer.Cancel(jobId)));
        }

        if (operation == "optimizer.cleanup_interrupted")
        {
            var itemId = RequireItemId(parameters);
            if (!parameters.TryGetValue("confirmation", out var confirmation)
                || confirmation.ValueKind != JsonValueKind.String
                || confirmation.GetString() != "YES_REMOVE_KAEVO_PARTIAL")
            {
                throw new InvalidOperationException("optimizerRecoveryConfirmationRequired");
            }
            var result = _optimizer.CleanInterruptedOutput(itemId);
            return CompleteCommand(request, operation, new { removed = result.Removed, state = result.State });
        }

        if (operation == "optimizer.pause_job")
        {
            var jobId = RequireGuid(parameters, "job_id", "optimizerJobInvalid");
            var durationMinutes = parameters.TryGetValue("duration_minutes", out var value) && value.TryGetInt32(out var supplied)
                ? Math.Clamp(supplied, 0, 720)
                : throw new InvalidOperationException("optimizerPauseDurationInvalid");
            return CompleteCommand(request, operation, OptimizerJobResult(
                _optimizer.Pause(jobId, durationMinutes == 0 ? null : TimeSpan.FromMinutes(durationMinutes))));
        }

        if (operation == "optimizer.resume_job")
        {
            var jobId = RequireGuid(parameters, "job_id", "optimizerJobInvalid");
            return CompleteCommand(request, operation, OptimizerJobResult(_optimizer.Resume(jobId)));
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

        if (operation == "jellyfin.delete_item")
        {
            if (!configuration.RemoteMediaDeletionEnabled)
            {
                throw new InvalidOperationException("remoteMediaDeletionDisabled");
            }

            var itemId = RequireItemId(parameters);
            await SendLocalAsync(
                configuration,
                secrets,
                HttpMethod.Delete,
                $"/Items/{itemId}",
                null,
                null,
                cancellationToken).ConfigureAwait(false);
            return new CommandResult(200, JsonSerializer.SerializeToElement(new
            {
                requestId = request.RequestId,
                state = "complete",
                operation,
                result = new { item_id = itemId, deleted = true }
            }, JsonOptions), false);
        }

        if (operation is "jellyfin.playback_started" or "jellyfin.playback_progress" or "jellyfin.playback_stopped")
        {
            if (!configuration.RemotePlaybackEnabled)
            {
                throw new InvalidOperationException("remotePlaybackDisabled");
            }

            var itemId = RequireItemId(parameters);
            var mediaSourceId = RequireString(parameters, "media_source_id", 128);
            var playSessionId = RequireString(parameters, "play_session_id", 128);
            var positionTicks = parameters.TryGetValue("position_ticks", out var ticksElement)
                && ticksElement.TryGetInt64(out var ticks) && ticks >= 0 ? ticks : 0;
            var isPaused = parameters.TryGetValue("is_paused", out var pausedElement)
                && (pausedElement.ValueKind is JsonValueKind.True or JsonValueKind.False)
                && pausedElement.GetBoolean();
            var endpoint = operation switch
            {
                "jellyfin.playback_started" => "/Sessions/Playing",
                "jellyfin.playback_progress" => "/Sessions/Playing/Progress",
                _ => "/Sessions/Playing/Stopped"
            };
            await SendLocalAsync(configuration, secrets, HttpMethod.Post, endpoint, null, new
            {
                ItemId = itemId,
                MediaSourceId = mediaSourceId,
                PlaySessionId = playSessionId,
                PositionTicks = positionTicks,
                IsPaused = isPaused,
                CanSeek = true
            }, cancellationToken).ConfigureAwait(false);
            return CompleteCommand(request, operation, new { item_id = itemId, position_ticks = positionTicks, applied = true });
        }

        if (operation == "provider.health")
        {
            var providerName = RequireProviderName(parameters);
            var health = await ReadProviderHealthAsync(secrets, providerName, cancellationToken).ConfigureAwait(false);
            return CompleteCommand(request, operation, health);
        }

        if (operation == "seerr.create_request")
        {
            var mediaType = RequireString(parameters, "media_type", 8).ToLowerInvariant();
            if (mediaType is not ("movie" or "tv"))
            {
                throw new InvalidOperationException("seerrMediaTypeInvalid");
            }
            var mediaId = RequirePositiveInt(parameters, "media_id");
            var seasons = parameters.TryGetValue("seasons", out var seasonsElement)
                && seasonsElement.ValueKind == JsonValueKind.Array
                ? seasonsElement.EnumerateArray().Where(value => value.TryGetInt32(out var season) && season > 0 && season <= 100).Select(value => value.GetInt32()).Distinct().Take(50).ToArray()
                : Array.Empty<int>();
            var is4K = parameters.TryGetValue("is_4k", out var fourKElement)
                && (fourKElement.ValueKind is JsonValueKind.True or JsonValueKind.False)
                && fourKElement.GetBoolean();
            var created = await SendSeerrJsonAsync(secrets, HttpMethod.Post, "/api/v1/request", new
            {
                mediaType,
                mediaId,
                seasons,
                is4k = is4K
            }, cancellationToken).ConfigureAwait(false);
            return CompleteCommand(request, operation, created);
        }

        if (operation == "seerr.cancel_request")
        {
            var requestId = RequirePositiveInt(parameters, "request_id");
            await SendSeerrJsonAsync(secrets, HttpMethod.Delete, $"/api/v1/request/{requestId}", null, cancellationToken).ConfigureAwait(false);
            return CompleteCommand(request, operation, new { request_id = requestId, cancelled = true });
        }

        if (operation == "sonarr.episode_inventory")
        {
            var tvdbId = RequirePositiveInt(parameters, "tvdb_id");
            var series = await SendSonarrJsonAsync(secrets, HttpMethod.Get, "/api/v3/series", null, cancellationToken).ConfigureAwait(false);
            var matches = series.EnumerateArray()
                .Where(item => item.TryGetProperty("tvdbId", out var value) && value.TryGetInt32(out var id) && id == tvdbId)
                .ToArray();
            if (matches.Length != 1 || !matches[0].TryGetProperty("id", out var seriesIdElement) || !seriesIdElement.TryGetInt32(out var seriesId))
            {
                throw new InvalidOperationException(matches.Length == 0 ? "sonarrSeriesNotFound" : "sonarrSeriesAmbiguous");
            }

            var episodes = await SendSonarrJsonAsync(secrets, HttpMethod.Get, $"/api/v3/episode?seriesId={seriesId}&includeImages=false", null, cancellationToken).ConfigureAwait(false);
            var queue = await SendSonarrJsonAsync(secrets, HttpMethod.Get, $"/api/v3/queue?seriesId={seriesId}&page=1&pageSize=1000", null, cancellationToken).ConfigureAwait(false);
            var files = await SendSonarrJsonAsync(secrets, HttpMethod.Get, $"/api/v3/episodefile?seriesId={seriesId}", null, cancellationToken).ConfigureAwait(false);
            return CompleteCommand(request, operation, new { series_id = seriesId, episodes, queue, files });
        }

        if (operation == "sonarr.search_episodes")
        {
            var episodeIds = RequirePositiveIds(parameters, "episode_ids");
            await SendSonarrJsonAsync(secrets, HttpMethod.Put, "/api/v3/episode/monitor", new { episodeIds, monitored = true }, cancellationToken).ConfigureAwait(false);
            var command = await SendSonarrJsonAsync(secrets, HttpMethod.Post, "/api/v3/command", new { name = "EpisodeSearch", episodeIds }, cancellationToken).ConfigureAwait(false);
            return CompleteCommand(request, operation, new { episode_ids = episodeIds, command });
        }

        if (operation == "sonarr.cancel_episodes")
        {
            var seriesId = RequirePositiveInt(parameters, "series_id");
            var episodeIds = RequirePositiveIds(parameters, "episode_ids");
            if (parameters.TryGetValue("command_ids", out var commandIdsElement)
                && commandIdsElement.ValueKind == JsonValueKind.Array)
            {
                var commandIds = commandIdsElement.EnumerateArray()
                    .Where(value => value.TryGetInt32(out var id) && id > 0)
                    .Select(value => value.GetInt32())
                    .Distinct()
                    .Take(500)
                    .ToArray();
                foreach (var commandId in commandIds)
                {
                    await SendSonarrJsonAsync(secrets, HttpMethod.Delete, $"/api/v3/command/{commandId}", null, cancellationToken).ConfigureAwait(false);
                }
            }
            await CancelSonarrEpisodesAsync(secrets, seriesId, episodeIds, cancellationToken).ConfigureAwait(false);
            return CompleteCommand(request, operation, new { episode_ids = episodeIds, cancelled = true });
        }

        if (operation == "sonarr.remove_episode_files")
        {
            var seriesId = RequirePositiveInt(parameters, "series_id");
            var episodeIds = RequirePositiveIds(parameters, "episode_ids");
            await CancelSonarrEpisodesAsync(secrets, seriesId, episodeIds, cancellationToken).ConfigureAwait(false);
            var files = await SendSonarrJsonAsync(secrets, HttpMethod.Get, $"/api/v3/episodefile?seriesId={seriesId}", null, cancellationToken).ConfigureAwait(false);
            var target = episodeIds.ToHashSet();
            foreach (var file in files.EnumerateArray())
            {
                if (!file.TryGetProperty("episodeIds", out var fileEpisodes) || fileEpisodes.ValueKind != JsonValueKind.Array)
                {
                    continue;
                }
                var contained = fileEpisodes.EnumerateArray().Where(value => value.TryGetInt32(out _)).Select(value => value.GetInt32()).ToArray();
                if (!contained.Any(target.Contains))
                {
                    continue;
                }
                if (contained.Any(id => !target.Contains(id)))
                {
                    throw new InvalidOperationException("sonarrMultiEpisodeFileUnsafe");
                }
                if (file.TryGetProperty("id", out var fileId) && fileId.TryGetInt32(out var id))
                {
                    await SendSonarrJsonAsync(secrets, HttpMethod.Delete, $"/api/v3/episodefile/{id}", null, cancellationToken).ConfigureAwait(false);
                }
            }
            await SendSonarrJsonAsync(secrets, HttpMethod.Put, "/api/v3/episode/monitor", new { episodeIds, monitored = false }, cancellationToken).ConfigureAwait(false);
            await SendLocalAsync(configuration, secrets, HttpMethod.Post, "/Library/Refresh", null, null, cancellationToken).ConfigureAwait(false);
            return CompleteCommand(request, operation, new { episode_ids = episodeIds, removed = true });
        }

        throw new InvalidOperationException("remoteCommandNotAllowed");
    }

    private static CommandResult CompleteCommand(CloudRequest request, string operation, object result)
    {
        return new CommandResult(200, JsonSerializer.SerializeToElement(new
        {
            requestId = request.RequestId,
            state = "complete",
            operation,
            result
        }, JsonOptions), false);
    }

    private async Task CancelSonarrEpisodesAsync(
        KaevoConnectorSecrets secrets,
        int seriesId,
        IReadOnlyList<int> episodeIds,
        CancellationToken cancellationToken)
    {
        var queuePayload = await SendSonarrJsonAsync(secrets, HttpMethod.Get, $"/api/v3/queue?seriesId={seriesId}&page=1&pageSize=1000", null, cancellationToken).ConfigureAwait(false);
        var records = queuePayload.TryGetProperty("records", out var value) && value.ValueKind == JsonValueKind.Array
            ? value.EnumerateArray().ToArray()
            : queuePayload.ValueKind == JsonValueKind.Array ? queuePayload.EnumerateArray().ToArray() : Array.Empty<JsonElement>();
        var target = episodeIds.ToHashSet();
        var matchingDownloadIds = records
            .Where(record => record.TryGetProperty("episodeId", out var episode) && episode.TryGetInt32(out var id) && target.Contains(id))
            .Select(record => record.TryGetProperty("downloadId", out var download) ? download.GetString() : null)
            .Where(id => !string.IsNullOrWhiteSpace(id))
            .ToHashSet(StringComparer.Ordinal);
        var related = records.Where(record =>
            record.TryGetProperty("downloadId", out var download)
            && matchingDownloadIds.Contains(download.GetString() ?? string.Empty)).ToArray();
        if (related.Any(record => record.TryGetProperty("episodeId", out var episode) && episode.TryGetInt32(out var id) && !target.Contains(id)))
        {
            throw new InvalidOperationException("sonarrSharedDownloadUnsafe");
        }
        foreach (var record in related)
        {
            if (record.TryGetProperty("id", out var queueId) && queueId.TryGetInt32(out var id))
            {
                await SendSonarrJsonAsync(secrets, HttpMethod.Delete, $"/api/v3/queue/{id}?removeFromClient=true&blocklist=true&skipRedownload=true&changeCategory=false", null, cancellationToken).ConfigureAwait(false);
            }
        }
        await SendSonarrJsonAsync(secrets, HttpMethod.Put, "/api/v3/episode/monitor", new { episodeIds, monitored = false }, cancellationToken).ConfigureAwait(false);
    }

    private async Task<JsonElement> SendSonarrJsonAsync(
        KaevoConnectorSecrets secrets,
        HttpMethod method,
        string path,
        object? body,
        CancellationToken cancellationToken)
    {
        var sonarr = secrets.GetProvider("sonarr");
        if (sonarr?.Enabled != true
            || !Uri.TryCreate(sonarr.BaseUrl, UriKind.Absolute, out var baseUri)
            || string.IsNullOrWhiteSpace(sonarr.ApiKey))
        {
            throw new InvalidOperationException("sonarrNotProvisioned");
        }
        var uri = new Uri(sonarr.BaseUrl.TrimEnd('/') + "/" + path.TrimStart('/'), UriKind.Absolute);
        using var message = new HttpRequestMessage(method, uri);
        message.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        message.Headers.Add("X-Api-Key", sonarr.ApiKey);
        if (body is not null)
        {
            message.Content = new StringContent(JsonSerializer.Serialize(body, JsonOptions), Encoding.UTF8, "application/json");
        }
        using var response = await _providerTransport.SendAsync("sonarr", sonarr, message, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        if ((int)response.StatusCode is >= 300 and < 400)
        {
            throw new InvalidOperationException("sonarrRedirectRejected");
        }
        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException($"sonarrHttp{(int)response.StatusCode}");
        }
        if (response.Content.Headers.ContentLength == 0 || method == HttpMethod.Delete)
        {
            return JsonSerializer.SerializeToElement(new { ok = true }, JsonOptions);
        }
        var bounded = await ReadBoundedAsync(response.Content, 2_000_000, cancellationToken).ConfigureAwait(false);
        if (bounded.Truncated) throw new InvalidOperationException("sonarrResponseTooLarge");
        using var document = JsonDocument.Parse(bounded.Data);
        return document.RootElement.Clone();
    }

    private async Task<JsonElement> SendSeerrJsonAsync(
        KaevoConnectorSecrets secrets,
        HttpMethod method,
        string path,
        object? body,
        CancellationToken cancellationToken)
    {
        var seerr = secrets.GetProvider("seerr");
        if (seerr?.Enabled != true
            || !Uri.TryCreate(seerr.BaseUrl, UriKind.Absolute, out var baseUri)
            || string.IsNullOrWhiteSpace(seerr.ApiKey))
        {
            throw new InvalidOperationException("seerrNotProvisioned");
        }
        var uri = new Uri(seerr.BaseUrl.TrimEnd('/') + "/" + path.TrimStart('/'), UriKind.Absolute);
        using var message = new HttpRequestMessage(method, uri);
        message.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        message.Headers.Add("X-Api-Key", seerr.ApiKey);
        if (body is not null)
        {
            message.Content = new StringContent(JsonSerializer.Serialize(body, JsonOptions), Encoding.UTF8, "application/json");
        }
        using var response = await _providerTransport.SendAsync("seerr", seerr, message, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        if ((int)response.StatusCode is >= 300 and < 400)
        {
            throw new InvalidOperationException("seerrRedirectRejected");
        }
        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException($"seerrHttp{(int)response.StatusCode}");
        }
        if (response.Content.Headers.ContentLength == 0 || method == HttpMethod.Delete)
        {
            return JsonSerializer.SerializeToElement(new { ok = true }, JsonOptions);
        }
        var bounded = await ReadBoundedAsync(response.Content, 2_000_000, cancellationToken).ConfigureAwait(false);
        if (bounded.Truncated) throw new InvalidOperationException("seerrResponseTooLarge");
        using var document = JsonDocument.Parse(bounded.Data);
        return document.RootElement.Clone();
    }

    private async Task<CommandResult> SendProviderReadAsync(
        PluginConfiguration configuration,
        KaevoConnectorSecrets secrets,
        string providerName,
        string path,
        IReadOnlyDictionary<string, JsonElement>? query,
        CancellationToken cancellationToken)
    {
        providerName = providerName.Trim().ToLowerInvariant();
        var provider = secrets.GetProvider(providerName);
        var requiresApiKey = providerName != "tdarr";
        if (provider?.Enabled != true
            || !Uri.TryCreate(provider.BaseUrl, UriKind.Absolute, out var baseUri)
            || (baseUri.Scheme != Uri.UriSchemeHttp && baseUri.Scheme != Uri.UriSchemeHttps)
            || (requiresApiKey && string.IsNullOrWhiteSpace(provider.ApiKey)))
        {
            throw new InvalidOperationException($"{providerName}NotProvisioned");
        }

        var uri = BuildProviderUri(baseUri, path, query);
        using var message = new HttpRequestMessage(HttpMethod.Get, uri);
        message.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        if (!string.IsNullOrWhiteSpace(provider.ApiKey))
        {
            message.Headers.TryAddWithoutValidation(
                providerName == "bazarr" ? "X-API-KEY" : "X-Api-Key",
                provider.ApiKey);
        }

        using var response = await _providerTransport.SendAsync(
            providerName,
            provider,
            message,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken).ConfigureAwait(false);
        if ((int)response.StatusCode is >= 300 and < 400)
        {
            throw new InvalidOperationException($"{providerName}RedirectRejected");
        }

        var bounded = await ReadBoundedAsync(
            response.Content,
            configuration.MaximumRemoteResponseBytes,
            cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException($"{providerName}Http{(int)response.StatusCode}");
        }

        var payload = bounded.Data.Length == 0
            ? JsonSerializer.SerializeToElement(new { state = "ok" }, JsonOptions)
            : JsonSerializer.Deserialize<JsonElement>(bounded.Data, JsonOptions);
        return new CommandResult((int)response.StatusCode, payload, bounded.Truncated);
    }

    private static Uri BuildProviderUri(
        Uri baseUri,
        string path,
        IReadOnlyDictionary<string, JsonElement>? query)
    {
        var uri = new Uri(baseUri.ToString().TrimEnd('/') + "/" + path.TrimStart('/'), UriKind.Absolute);
        if (query is null || query.Count == 0)
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

    private async Task<object> ReadProviderHealthAsync(
        KaevoConnectorSecrets secrets,
        string providerName,
        CancellationToken cancellationToken)
    {
        var provider = secrets.GetProvider(providerName);
        var requiresApiKey = providerName != "tdarr";
        if (provider?.Enabled != true
            || !Uri.TryCreate(provider.BaseUrl, UriKind.Absolute, out _)
            || (requiresApiKey && string.IsNullOrWhiteSpace(provider.ApiKey)))
        {
            throw new InvalidOperationException($"{providerName}NotProvisioned");
        }

        var path = providerName switch
        {
            "seerr" => "/api/v1/status",
            "bazarr" => "/api/system/status",
            "tdarr" => "/api/v2/status",
            "lidarr" or "readarr" or "prowlarr" => "/api/v1/system/status",
            _ => "/api/v3/system/status"
        };
        var uri = new Uri(provider.BaseUrl.TrimEnd('/') + path, UriKind.Absolute);
        using var message = new HttpRequestMessage(HttpMethod.Get, uri);
        message.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        if (!string.IsNullOrWhiteSpace(provider.ApiKey))
        {
            message.Headers.TryAddWithoutValidation(providerName == "bazarr" ? "X-API-KEY" : "X-Api-Key", provider.ApiKey);
        }

        using var response = await _providerTransport.SendAsync(providerName, provider, message, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        if ((int)response.StatusCode is >= 300 and < 400)
        {
            throw new InvalidOperationException($"{providerName}RedirectRejected");
        }
        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException($"{providerName}Http{(int)response.StatusCode}");
        }

        var bounded = await ReadBoundedAsync(response.Content, 1_000_000, cancellationToken).ConfigureAwait(false);
        if (bounded.Truncated) throw new InvalidOperationException($"{providerName}ResponseTooLarge");
        string? version;
        try
        {
            version = ValidateProviderHealthResponse(bounded.Data, response.Content.Headers.ContentType?.MediaType);
        }
        catch (JsonException)
        {
            throw new InvalidOperationException($"{providerName}ResponseMalformed");
        }

        return new { provider = providerName, reachable = true, version };
    }

    internal static string? ValidateProviderHealthResponse(byte[] data, string? mediaType)
    {
        if (data.Length == 0
            || string.IsNullOrWhiteSpace(mediaType)
            || !(mediaType.Equals("application/json", StringComparison.OrdinalIgnoreCase)
                || mediaType.EndsWith("+json", StringComparison.OrdinalIgnoreCase)))
        {
            throw new JsonException("Provider health response is not JSON.");
        }

        using var document = JsonDocument.Parse(data);
        RejectDuplicateProperties(document.RootElement);
        if (document.RootElement.ValueKind != JsonValueKind.Object)
        {
            throw new JsonException("Provider health response root must be an object.");
        }

        return document.RootElement.TryGetProperty("version", out var versionElement)
            && versionElement.ValueKind == JsonValueKind.String
                ? versionElement.GetString()
                : null;
    }

    private static void RejectDuplicateProperties(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name)) throw new JsonException("Provider response contains duplicate properties.");
                RejectDuplicateProperties(property.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray()) RejectDuplicateProperties(item);
        }
    }

    private static string RequireProviderName(IReadOnlyDictionary<string, JsonElement> parameters)
    {
        if (!parameters.TryGetValue("provider", out var value)
            || value.ValueKind != JsonValueKind.String)
        {
            throw new InvalidOperationException("providerParameterInvalid");
        }
        var providerName = value.GetString()?.Trim().ToLowerInvariant() ?? string.Empty;
        if (!SupportedLocalProviders.Contains(providerName))
        {
            throw new InvalidOperationException("providerNotAllowed");
        }
        return providerName;
    }

    private static int RequirePositiveInt(IReadOnlyDictionary<string, JsonElement> parameters, string key)
    {
        if (!parameters.TryGetValue(key, out var value) || !value.TryGetInt32(out var result) || result <= 0)
        {
            throw new InvalidOperationException("sonarrParameterInvalid");
        }
        return result;
    }

    private static int? OptionalNonNegativeInt(IReadOnlyDictionary<string, JsonElement> parameters, string key)
    {
        if (!parameters.TryGetValue(key, out var value) || value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }
        if (!value.TryGetInt32(out var result) || result < 0 || result > 10_000)
        {
            throw new InvalidOperationException("playbackStreamIndexInvalid");
        }
        return result;
    }

    private static string RequireString(
        IReadOnlyDictionary<string, JsonElement> parameters,
        string key,
        int maximumLength)
    {
        if (!parameters.TryGetValue(key, out var value)
            || value.ValueKind != JsonValueKind.String)
        {
            throw new InvalidOperationException("commandParameterInvalid");
        }

        var result = value.GetString()?.Trim() ?? string.Empty;
        if (result.Length == 0
            || result.Length > maximumLength
            || !SafeIdentifierRegex().IsMatch(result))
        {
            throw new InvalidOperationException("commandParameterInvalid");
        }

        return result;
    }

    private static int[] RequirePositiveIds(IReadOnlyDictionary<string, JsonElement> parameters, string key)
    {
        if (!parameters.TryGetValue(key, out var value) || value.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidOperationException("sonarrEpisodeIdsInvalid");
        }
        var ids = value.EnumerateArray().Where(item => item.TryGetInt32(out var id) && id > 0).Select(item => item.GetInt32()).Distinct().Take(500).ToArray();
        if (ids.Length == 0)
        {
            throw new InvalidOperationException("sonarrEpisodeIdsInvalid");
        }
        return ids;
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

        var requestedBitrate = parameters.TryGetValue("max_bitrate", out var bitrate) && bitrate.TryGetInt32(out var supplied)
            ? supplied
            : (int?)null;
        var maxBitrate = KaevoPlaybackProfilePolicy.ClampRemoteBitrate(
            configuration.MaximumPlaybackBitrate,
            requestedBitrate);
        var audioStreamIndex = OptionalNonNegativeInt(parameters, "audio_stream_index");
        var subtitleStreamIndex = OptionalNonNegativeInt(parameters, "subtitle_stream_index");
        var compatibilityPlayer = parameters.TryGetValue("compatibility_player", out var compatibility)
            && compatibility.ValueKind is JsonValueKind.True or JsonValueKind.False
            && compatibility.GetBoolean();
        var body = new
        {
            UserId = configuration.JellyfinUserId,
            AudioStreamIndex = audioStreamIndex,
            SubtitleStreamIndex = subtitleStreamIndex,
            MaxStreamingBitrate = maxBitrate,
            EnableDirectPlay = false,
            EnableDirectStream = true,
            EnableTranscoding = true,
            AllowVideoStreamCopy = true,
            AllowAudioStreamCopy = false,
            EnableAutoStreamCopy = false,
            DeviceProfile = KaevoPlaybackProfilePolicy.BuildAppleHlsDeviceProfile(maxBitrate)
        };
        var playbackInfoQuery = new List<string>
        {
            $"UserId={Uri.EscapeDataString(configuration.JellyfinUserId)}"
        };
        if (audioStreamIndex is not null)
        {
            playbackInfoQuery.Add($"AudioStreamIndex={audioStreamIndex.Value}");
        }
        if (subtitleStreamIndex is not null)
        {
            playbackInfoQuery.Add($"SubtitleStreamIndex={subtitleStreamIndex.Value}");
        }
        var local = await SendLocalAsync(
            configuration,
            secrets,
            HttpMethod.Post,
            $"/Items/{itemId}/PlaybackInfo?{string.Join("&", playbackInfoQuery)}",
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
        if (KaevoPlaybackSourcePolicy.IsDiscImage(source))
        {
            throw new InvalidOperationException("playbackDiscImageUnsupported");
        }

        var mediaSourceId = source.TryGetProperty("Id", out var sourceId) ? sourceId.GetString() : null;
        var playSessionId = root.TryGetProperty("PlaySessionId", out var sessionId) ? sessionId.GetString() : null;
        if (string.IsNullOrWhiteSpace(mediaSourceId) || string.IsNullOrWhiteSpace(playSessionId))
        {
            throw new InvalidOperationException("playbackIdentifiersMissing");
        }

        var remux = source.TryGetProperty("SupportsDirectStream", out var streamValue) && streamValue.GetBoolean();
        var mode = compatibilityPlayer ? "direct_play" : remux ? "remux" : "transcode";
        var tracks = KaevoPlaybackTrackCatalog.FromMediaSource(source);
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
                max_bitrate = maxBitrate,
                audio_tracks = tracks.AudioTracks,
                subtitle_tracks = tracks.SubtitleTracks,
                selected_audio_stream_index = audioStreamIndex ?? tracks.SelectedAudioStreamIndex,
                selected_subtitle_stream_index = subtitleStreamIndex
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
        var recentLimit = Math.Clamp(QueryInt(query, "recentLimit", 30), 1, 50);
        var viewsTask = SendLocalAsync(configuration, secrets, HttpMethod.Get, $"/Users/{userId}/Views", null, null, cancellationToken);
        var moviesTask = ReadSnapshotItemsAsync(configuration, secrets, userId, "Movie", moviesLimit, null, cancellationToken);
        var showsTask = ReadSnapshotItemsAsync(configuration, secrets, userId, "Series", showsLimit, null, cancellationToken);
        var collectionsTask = ReadSnapshotItemsAsync(configuration, secrets, userId, "BoxSet", collectionsLimit, null, cancellationToken);
        var resumeTask = ReadSnapshotItemsAsync(configuration, secrets, userId, "Movie,Episode", resumeLimit, true, cancellationToken);
        var recentTask = ReadSnapshotItemsAsync(configuration, secrets, userId, "Movie,Episode", recentLimit, null, cancellationToken);
        await Task.WhenAll(viewsTask, moviesTask, showsTask, collectionsTask, resumeTask, recentTask).ConfigureAwait(false);
        return new CommandResult(200, JsonSerializer.SerializeToElement(new
        {
            version = "0.2.49",
            generated_at = DateTimeOffset.UtcNow,
            views = viewsTask.Result.Payload,
            movies = moviesTask.Result.Payload,
            shows = showsTask.Result.Payload,
            collections = collectionsTask.Result.Payload,
            continueWatching = resumeTask.Result.Payload,
            recentlyAdded = recentTask.Result.Payload,
            limits = new { movies_limit = moviesLimit, shows_limit = showsLimit, collections_limit = collectionsLimit, resume_limit = resumeLimit, recent_limit = recentLimit }
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
            ["SortBy"] = JsonSerializer.SerializeToElement(isResumable == true ? "DatePlayed" : "DateCreated"),
            ["SortOrder"] = JsonSerializer.SerializeToElement("Descending")
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
        var active = new ConcurrentDictionary<string, RelayRequestContext>(StringComparer.Ordinal);
        _state.RelayConnected();
        try
        {
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
                else if (message.Type == "body_ack" && active.TryGetValue(message.RequestId, out var acknowledged))
                {
                    acknowledged.AcknowledgeBody();
                }
                else if (message.Type == "cancel" && active.TryGetValue(message.RequestId, out var existing))
                {
                    existing.Cancel();
                }
                else if (message.Type == "request" && !string.IsNullOrWhiteSpace(message.Grant))
                {
                    var context = new RelayRequestContext(cancellationToken);
                    if (!active.TryAdd(message.RequestId, context))
                    {
                        context.Dispose();
                        continue;
                    }

                    _ = ProcessRelayRequestAsync(
                        configuration,
                        secrets,
                        socket,
                        sendGate,
                        message,
                        context,
                        active);
                }
            }
        }
        finally
        {
            _state.RelayDisconnected();
            foreach (var context in active.Values)
            {
                context.Cancel();
            }
        }
    }

    private Task RunRelayPoolAsync(
        PluginConfiguration configuration,
        KaevoConnectorSecrets secrets,
        CancellationToken cancellationToken)
        => Task.WhenAll(Enumerable.Range(0, RelayChannelCount)
            .Select(_ => RunRelaySupervisorAsync(configuration, secrets, cancellationToken)));

    private async Task ProcessRelayRequestAsync(
        PluginConfiguration configuration,
        KaevoConnectorSecrets secrets,
        ClientWebSocket socket,
        SemaphoreSlim sendGate,
        RelayMessage message,
        RelayRequestContext context,
        ConcurrentDictionary<string, RelayRequestContext> active)
    {
        try
        {
            await HandleRelayRequestAsync(configuration, secrets, socket, sendGate, message, context).ConfigureAwait(false);
        }
        finally
        {
            if (active.TryRemove(message.RequestId, out var completed))
            {
                completed.Dispose();
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
                _state.SetRelayError(SanitizeError(exception));
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
        RelayRequestContext context)
    {
        var cancellationToken = context.Token;
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
                // A feature-length Jellyfin VOD manifest can exceed 1 MiB
                // because every segment carries a bounded playback query. The
                // relay independently enforces the same 2 MiB ceiling.
                var playlist = await ReadBoundedAsync(response.Content, 2 * 1_048_576, cancellationToken).ConfigureAwait(false);
                if (playlist.Truncated)
                {
                    throw new InvalidOperationException("playlistTooLarge");
                }

                var rewritten = KaevoPlaybackPlaylistRewriter.Rewrite(
                    Encoding.UTF8.GetString(playlist.Data),
                    message.Grant!,
                    grant.ItemId,
                    grant.MediaSourceId,
                    resolved.PathAndQuery);
                var prefix = Encoding.ASCII.GetBytes(message.RequestId);
                var body = Encoding.UTF8.GetBytes(rewritten);
                var payload = new byte[prefix.Length + body.Length];
                prefix.CopyTo(payload, 0);
                body.CopyTo(payload, prefix.Length);
                await SendRelayBodyAsync(socket, sendGate, payload, context).ConfigureAwait(false);
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
                    await SendRelayBodyAsync(socket, sendGate, payload, context).ConfigureAwait(false);
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
            try
            {
                await SendTextAsync(socket, sendGate, JsonSerializer.Serialize(new
                {
                    type = "error",
                    request_id = message.RequestId,
                    category = SanitizeError(exception)
                }, JsonOptions), cancellationToken).ConfigureAwait(false);
            }
            catch (Exception sendException) when (sendException is OperationCanceledException or WebSocketException or ObjectDisposedException)
            {
                // The viewer or relay already closed this request. The relay
                // supervisor owns reconnecting the shared socket if needed.
            }
        }
    }

    private static async Task SendRelayBodyAsync(
        ClientWebSocket socket,
        SemaphoreSlim sendGate,
        byte[] payload,
        RelayRequestContext context)
    {
        // Protocol v3 transfers ownership as soon as the WebSocket send
        // completes. The relay enforces a bounded per-request queue and
        // cancels only that request if its viewer stops draining. Avoiding a
        // control-message round trip here prevents a dropped body ACK from
        // deadlocking every HLS playlist and segment.
        await SendBinaryAsync(socket, sendGate, payload, context.Token).ConfigureAwait(false);
    }

    private async Task<T> SendCloudAsync<T>(
        PluginConfiguration configuration,
        KaevoConnectorSecrets? secrets,
        HttpMethod method,
        string path,
        object body,
        CancellationToken cancellationToken)
    {
        if (secrets is null) throw new InvalidOperationException("lifecycle_upgrade_required");
        using var response = await _lifecycleClient.SendConnectorAsync(
            new Uri(configuration.CloudBaseUrl, UriKind.Absolute), method, path, body, cancellationToken).ConfigureAwait(false);
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
        if (KaevoPlugin.Instance?.PackageIntegrityValid != true)
        {
            throw new InvalidOperationException("pluginPackageVersionMismatch");
        }
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

    internal static bool IsAllowedProviderReadPath(string provider, string path)
    {
        if (string.IsNullOrWhiteSpace(path)
            || !path.StartsWith("/", StringComparison.Ordinal)
            || path.Contains("://", StringComparison.Ordinal)
            || path.Contains("..", StringComparison.Ordinal))
        {
            return false;
        }

        var prefixes = provider.ToLowerInvariant() switch
        {
            "sonarr" => new[] { "/api/v3/system/status", "/api/v3/series", "/api/v3/queue", "/api/v3/history", "/api/v3/wanted/missing" },
            "radarr" => new[] { "/api/v3/system/status", "/api/v3/movie", "/api/v3/queue", "/api/v3/history", "/api/v3/wanted/missing" },
            "seerr" => new[] { "/api/v1/status", "/api/v1/search", "/api/v1/discover/trending", "/api/v1/discover/movies", "/api/v1/discover/tv", "/api/v1/request", "/api/v1/media/", "/api/v1/movie/", "/api/v1/tv/" },
            "lidarr" => new[] { "/api/v1/system/status", "/api/v1/artist", "/api/v1/queue", "/api/v1/history", "/api/v1/wanted/missing" },
            "readarr" => new[] { "/api/v1/system/status", "/api/v1/author", "/api/v1/book", "/api/v1/queue", "/api/v1/history", "/api/v1/wanted/missing" },
            "prowlarr" => new[] { "/api/v1/system/status", "/api/v1/indexer", "/api/v1/indexerstatus" },
            "bazarr" => new[] { "/api/system/status" },
            "tdarr" => new[] { "/api/v2/status" },
            _ => Array.Empty<string>()
        };
        return prefixes.Any(prefix => path.StartsWith(prefix, StringComparison.Ordinal));
    }

    private static bool HasUnsafeProviderQuery(IReadOnlyDictionary<string, JsonElement>? query)
    {
        if (query is null)
        {
            return false;
        }

        if (query.Count > 40)
        {
            return true;
        }

        var blocked = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "apikey", "api_key", "token", "password", "pass", "key", "auth"
        };
        return query.Any(pair => blocked.Contains(pair.Key) || pair.Value.ToString().Length > 2_048);
    }

    private static string RequireItemId(IReadOnlyDictionary<string, JsonElement> parameters)
    {
        var value = parameters.TryGetValue("item_id", out var item) ? item.GetString() ?? string.Empty : string.Empty;
        if (!ItemIdRegex().IsMatch(value))
        {
            throw new InvalidOperationException("jellyfinItemIdInvalid");
        }

        return value.ToLowerInvariant();
    }

    private static Guid RequireGuid(
        IReadOnlyDictionary<string, JsonElement> parameters,
        string key,
        string error)
    {
        var value = parameters.TryGetValue(key, out var element) && element.ValueKind == JsonValueKind.String
            ? element.GetString()
            : null;
        return Guid.TryParse(value, out var result)
            ? result
            : throw new InvalidOperationException(error);
    }

    private static string RequireString(
        IReadOnlyDictionary<string, JsonElement> parameters,
        string key,
        string error)
    {
        var value = parameters.TryGetValue(key, out var element) && element.ValueKind == JsonValueKind.String
            ? element.GetString()
            : null;
        return !string.IsNullOrWhiteSpace(value)
            ? value
            : throw new InvalidOperationException(error);
    }

    private static object OptimizerJobResult(OptimizerJob job)
        => new
        {
            job_id = job.JobId,
            plan_id = job.PlanId,
            item_id = job.ItemId,
            title = job.Title,
            state = job.State,
            stage = job.Stage,
            progress = job.Progress,
            error = job.Error,
            source_bytes = job.SourceBytes,
            output_bytes = job.OutputBytes,
            queue_position = job.QueuePosition,
            paused_until = job.PausedUntil
        };

    private static string QueryString(IReadOnlyDictionary<string, JsonElement>? query, string key)
        => query is not null && query.TryGetValue(key, out var value)
            ? value.ValueKind == JsonValueKind.String ? value.GetString() ?? string.Empty : value.ToString()
            : string.Empty;

    private static int QueryInt(IReadOnlyDictionary<string, JsonElement>? query, string key, int fallback)
        => int.TryParse(QueryString(query, key), out var value) ? value : fallback;

    internal static async Task<(byte[] Data, bool Truncated)> ReadBoundedAsync(
        HttpContent content,
        int maximum,
        CancellationToken cancellationToken,
        TimeSpan? totalTimeout = null,
        TimeSpan? idleTimeout = null)
    {
        using var total = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        total.CancelAfter(totalTimeout ?? TimeSpan.FromSeconds(30));
        using var idle = CancellationTokenSource.CreateLinkedTokenSource(total.Token);
        var idleBudget = idleTimeout ?? TimeSpan.FromSeconds(5);
        idle.CancelAfter(idleBudget);
        await using var input = await content.ReadAsStreamAsync(idle.Token).ConfigureAwait(false);
        await using var output = new MemoryStream();
        var buffer = new byte[64 * 1024];
        var truncated = false;
        while (true)
        {
            var count = await input.ReadAsync(buffer, idle.Token).ConfigureAwait(false);
            if (count == 0)
            {
                break;
            }

            idle.CancelAfter(idleBudget);

            var remaining = maximum - checked((int)output.Length);
            if (remaining <= 0)
            {
                truncated = true;
                break;
            }

            await output.WriteAsync(buffer.AsMemory(0, Math.Min(count, remaining)), idle.Token).ConfigureAwait(false);
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

    private static IReadOnlyDictionary<string, ProviderReachability> BuildProviderStatus(
        KaevoConnectorSecrets secrets,
        PluginConfiguration configuration,
        bool includeOptimizer)
    {
        var result = new Dictionary<string, ProviderReachability>(StringComparer.OrdinalIgnoreCase)
        {
            ["jellyfin"] = ProviderStatus(true, true, "0.2.49", null)
        };
        foreach (var providerName in new[] { "sonarr", "radarr", "seerr", "lidarr", "readarr", "prowlarr", "bazarr", "tdarr" })
        {
            var provider = secrets.GetProvider(providerName);
            var requiresApiKey = providerName != "tdarr";
            var configured = provider is not null
                && Uri.TryCreate(provider.BaseUrl, UriKind.Absolute, out _)
                && (!requiresApiKey || !string.IsNullOrWhiteSpace(provider.ApiKey));
            var enabled = provider?.Enabled == true;
            result[providerName] = ProviderStatus(
                enabled && configured,
                configured,
                "0.2.49",
                !configured ? "notConfigured" : enabled ? null : "disabled");
        }

        if (includeOptimizer)
        {
            result["optimizer"] = ProviderStatus(
                configuration.OptimizerPlanningEnabled,
                configuration.OptimizerPlanningEnabled,
                "0.2.49",
                configuration.OptimizerPlanningEnabled ? null : "disabled");
        }
        result["playback_tunnel"] = ProviderStatus(
            configuration.RemotePlaybackEnabled,
            configuration.RemotePlaybackEnabled,
            "0.2.49",
            configuration.RemotePlaybackEnabled ? null : "disabled");
        return result;
    }

    internal sealed class RelayRequestContext : IDisposable
    {
        private readonly CancellationTokenSource _cancellation;
        private readonly SemaphoreSlim _bodyAcknowledged = new(0, 1);

        public RelayRequestContext(CancellationToken cancellationToken)
        {
            _cancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        }

        public CancellationToken Token => _cancellation.Token;

        public void AcknowledgeBody()
        {
            try
            {
                _bodyAcknowledged.Release();
            }
            catch (Exception exception) when (exception is SemaphoreFullException or ObjectDisposedException)
            {
                // Duplicate acknowledgements cannot enlarge the one-chunk
                // flow-control window. A late acknowledgement may also race
                // normal request cleanup and is safe to ignore.
            }
        }

        public void Cancel()
        {
            try
            {
                _cancellation.Cancel();
            }
            catch (ObjectDisposedException)
            {
                // Relay cancellation can arrive immediately after the request
                // task removes and disposes its context.
            }
        }

        public Task<bool> WaitForBodyAcknowledgementAsync(TimeSpan timeout)
            => _bodyAcknowledged.WaitAsync(timeout, _cancellation.Token);

        public void Dispose()
        {
            _cancellation.Dispose();
            _bodyAcknowledged.Dispose();
        }
    }

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
