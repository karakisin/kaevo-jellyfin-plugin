using System.Collections;
using Jellyfin.Data.Enums;
using MediaBrowser.Controller.Drawing;
using MediaBrowser.Controller.Entities;
using MediaBrowser.Controller.Library;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Kaevo.Plugin.KaevoForJellyfin.Models;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using QRCoder;

namespace Kaevo.Plugin.KaevoForJellyfin.Api;

[ApiController]
[Authorize]
[Route("kaevo")]
[Produces("application/json")]
public sealed class KaevoController : ControllerBase, IActionFilter
{
    private static readonly IReadOnlyDictionary<string, (string DisplayName, bool RequiresApiKey)> SupportedProviders =
        new Dictionary<string, (string DisplayName, bool RequiresApiKey)>(StringComparer.OrdinalIgnoreCase)
        {
            ["sonarr"] = ("Sonarr", true),
            ["radarr"] = ("Radarr", true),
            ["seerr"] = ("Seerr", true),
            ["lidarr"] = ("Lidarr", true),
            ["readarr"] = ("Readarr", true),
            ["prowlarr"] = ("Prowlarr", true),
            ["bazarr"] = ("Bazarr", true),
            ["tdarr"] = ("Tdarr", false)
        };
    private const int DefaultItemLimit = 50;
    private const int MaximumItemLimit = 100;
    private readonly ILibraryManager _libraryManager;
    private readonly IUserManager _userManager;
    private readonly IImageProcessor _imageProcessor;
    private readonly KaevoCloudState _cloudState;
    private readonly KaevoSecretStore _secretStore;
    private readonly KaevoProviderDestinationPolicy _providerPolicy;
    private readonly KaevoConnectorLifecycleClient _lifecycleClient;
    private readonly KaevoConnectorLifecycleStore _lifecycleStore;
    private readonly KaevoLocalPairingService _localPairing;
    private readonly KaevoProviderPolicyAuditStore _providerAudit;

    public KaevoController(
        ILibraryManager libraryManager,
        IUserManager userManager,
        IImageProcessor imageProcessor,
        KaevoCloudState cloudState,
        KaevoSecretStore secretStore,
        KaevoProviderDestinationPolicy providerPolicy,
        KaevoConnectorLifecycleClient lifecycleClient,
        KaevoConnectorLifecycleStore lifecycleStore,
        KaevoLocalPairingService localPairing,
        KaevoProviderPolicyAuditStore providerAudit)
    {
        _libraryManager = libraryManager;
        _userManager = userManager;
        _imageProcessor = imageProcessor;
        _cloudState = cloudState;
        _secretStore = secretStore;
        _providerPolicy = providerPolicy;
        _lifecycleClient = lifecycleClient;
        _lifecycleStore = lifecycleStore;
        _localPairing = localPairing;
        _providerAudit = providerAudit;
    }

    public void OnActionExecuting(ActionExecutingContext context)
    {
        if (KaevoPlugin.Instance?.PackageIntegrityValid != true)
        {
            context.Result = StatusCode(503, new { state = "pluginPackageVersionMismatch" });
        }
    }

    public void OnActionExecuted(ActionExecutedContext context) { }

    [AllowAnonymous]
    [HttpGet("branding/{asset}")]
    [Produces("image/png")]
    [ResponseCache(Duration = 86400, Location = ResponseCacheLocation.Client)]
    public IActionResult GetBrandingAsset(string asset)
    {
        var resourceName = asset.ToLowerInvariant() switch
        {
            "logo" => "Kaevo.Plugin.KaevoForJellyfin.Configuration.Branding.Kaevo_LogoMark_Transparent.png",
            "wordmark" => "Kaevo.Plugin.KaevoForJellyfin.Configuration.Branding.Kaevo_Wordmark_Transparent.png",
            _ => null
        };
        if (resourceName is null)
        {
            return NotFound();
        }

        var stream = typeof(KaevoController).Assembly.GetManifestResourceStream(resourceName);
        return stream is null ? NotFound() : File(stream, "image/png");
    }

    [HttpGet("status")]
    public ActionResult<KaevoStatusResponse> GetStatus()
    {
        var configuration = KaevoPlugin.Instance?.Configuration ?? new Configuration.PluginConfiguration();
        var cloud = _cloudState.Snapshot();
        var relay = _cloudState.RelaySnapshot();
        return Ok(new KaevoStatusResponse(
            "ok",
            "Kaevo",
            "0.2.54",
            configuration.CloudConnectorEnabled,
            cloud.Status,
            cloud.LastHeartbeatUtc,
            configuration.RemoteMetadataEnabled,
            configuration.RemoteWritesEnabled,
            configuration.RemotePlaybackEnabled,
            relay.Status,
            relay.LastConnectedUtc,
            relay.ConnectedChannels,
            "hls-bounded-buffer-v3",
            configuration.OptimizerExecutionEnabled));
    }

    [HttpGet("cloud/status")]
    public ActionResult<KaevoCloudPairingStatus> GetCloudStatus()
    {
        var cloud = _cloudState.Snapshot();
        return Ok(new KaevoCloudPairingStatus(
            cloud.Status,
            cloud.LastHeartbeatUtc,
            cloud.LastError));
    }

    [Authorize(Policy = "RequiresElevation")]
    [HttpPost("local-pairing/start")]
    public ActionResult<KaevoLocalPairingStartResponse> StartLocalPairing()
    {
        var ticket = _localPairing.Start();
        var baseUrl = $"{Request.Scheme}://{Request.Host}{Request.PathBase}".TrimEnd('/');
        var pairingUri = $"kaevo://home-pair?server={Uri.EscapeDataString(baseUrl)}&code={Uri.EscapeDataString(ticket.Code)}";
        using var data = QRCodeGenerator.GenerateQrCode(pairingUri, QRCodeGenerator.ECCLevel.Q);
        var png = new PngByteQRCode(data).GetGraphic(8);
        return Ok(new KaevoLocalPairingStartResponse(ticket.Code, ticket.ExpiresAtUtc, pairingUri, Convert.ToBase64String(png)));
    }

    [Authorize(Policy = "RequiresElevation")]
    [HttpPost("local-pairing/claim")]
    public async Task<ActionResult<KaevoLifecycleResponse>> ClaimLocalPairing(
        [FromBody] KaevoLocalPairingClaimRequest request,
        CancellationToken cancellationToken)
    {
        if (!TryCloudUri(request.CloudBaseUrl, out var cloud)
            || !ValidOwnerToken(request.OwnerAccessToken)
            || string.IsNullOrWhiteSpace(request.ProfileId)
            || string.IsNullOrWhiteSpace(request.JellyfinAccessToken)
            || !_localPairing.Consume(request.Code))
        {
            return BadRequest(new KaevoLifecycleResponse("invalid_or_expired", 0));
        }
        return await CompletePairing(cloud, request.OwnerAccessToken, request.ProfileId,
            request.JellyfinUserId, request.JellyfinAccessToken, cancellationToken).ConfigureAwait(false);
    }

    [Authorize(Policy = "RequiresElevation")]
    [HttpPost("cloud/activate")]
    public async Task<ActionResult<KaevoCloudActivationResponse>> ActivateCloud(
        [FromBody] KaevoCloudActivationRequest request,
        CancellationToken cancellationToken)
    {
        await Task.CompletedTask;
        return Conflict(new KaevoCloudActivationResponse("lifecycle_upgrade_required", "Use the lifecycle enrollment action."));
    }

    [Authorize(Policy = "RequiresElevation")]
    [HttpPost("cloud/lifecycle/pair")]
    public async Task<ActionResult<KaevoLifecycleResponse>> PairLifecycle(
        [FromBody] KaevoLifecyclePairRequest request,
        [FromHeader(Name = "X-Kaevo-Admin-Action")] string adminAction,
        CancellationToken cancellationToken)
    {
        if (!ValidAdminAction(adminAction) || !TryCloudUri(request.CloudBaseUrl, out var cloud)
            || !ValidOwnerToken(request.OwnerAccessToken) || string.IsNullOrWhiteSpace(request.ProfileId)
            || string.IsNullOrWhiteSpace(request.JellyfinAccessToken))
        {
            return BadRequest(new KaevoLifecycleResponse("invalid", 0));
        }
        return await CompletePairing(cloud, request.OwnerAccessToken, request.ProfileId,
            request.JellyfinUserId, request.JellyfinAccessToken, cancellationToken).ConfigureAwait(false);
    }

    private async Task<ActionResult<KaevoLifecycleResponse>> CompletePairing(
        Uri cloud,
        string ownerAccessToken,
        string profileId,
        string jellyfinUserId,
        string jellyfinAccessToken,
        CancellationToken cancellationToken)
    {
        var result = await _lifecycleClient.PairAsync(cloud, ownerAccessToken, profileId.Trim(), cancellationToken).ConfigureAwait(false);
        var existing = await _secretStore.ReadAsync(cancellationToken).ConfigureAwait(false);
        await _secretStore.WriteAsync(new KaevoConnectorSecrets(
            string.Empty, string.Empty, jellyfinAccessToken,
            existing?.SonarrBaseUrl ?? string.Empty, existing?.SonarrApiKey ?? string.Empty, existing?.Providers), cancellationToken).ConfigureAwait(false);
        var configuration = KaevoPlugin.Instance?.Configuration;
        if (configuration is null) return StatusCode(503, new KaevoLifecycleResponse("unavailable", 0));
        configuration.CloudBaseUrl = cloud.ToString().TrimEnd('/');
        configuration.ProfileId = profileId.Trim();
        configuration.ConnectorId = result.ConnectorId;
        configuration.PairingCode = string.Empty;
        configuration.LocalJellyfinBaseUrl = "http://127.0.0.1:8096";
        configuration.JellyfinUserId = jellyfinUserId.Trim();
        configuration.CloudConnectorEnabled = true;
        configuration.RemoteMetadataEnabled = true;
        configuration.RemoteArtworkEnabled = true;
        configuration.RemoteWritesEnabled = true;
        configuration.RemoteMediaDeletionEnabled = false;
        configuration.RemotePlaybackEnabled = false;
        configuration.OptimizerPlanningEnabled = true;
        configuration.OptimizerExecutionEnabled = false;
        KaevoPlugin.Instance?.SaveConfiguration();
        _cloudState.Set("connecting");
        _cloudState.SignalConfigurationChanged();
        return Ok(new KaevoLifecycleResponse(result.State, result.CredentialVersion));
    }

    [Authorize(Policy = "RequiresElevation")]
    [HttpPost("cloud/lifecycle/rotate")]
    public Task<ActionResult<KaevoLifecycleResponse>> RotateLifecycle([FromBody] KaevoLifecycleOwnerRequest request, [FromHeader(Name = "X-Kaevo-Admin-Action")] string action, CancellationToken token) =>
        RunLifecycleOwnerAction(request, action, (uri, owner, profile) => _lifecycleClient.RotateAsync(uri, owner, profile, token));

    [Authorize(Policy = "RequiresElevation")]
    [HttpPost("cloud/lifecycle/recover")]
    public Task<ActionResult<KaevoLifecycleResponse>> RecoverLifecycle([FromBody] KaevoLifecycleOwnerRequest request, [FromHeader(Name = "X-Kaevo-Admin-Action")] string action, CancellationToken token) =>
        RunLifecycleOwnerAction(request, action, (uri, owner, profile) => _lifecycleClient.RecoverAsync(uri, owner, profile, token));

    [Authorize(Policy = "RequiresElevation")]
    [HttpPost("cloud/lifecycle/revoke")]
    public Task<ActionResult<KaevoLifecycleResponse>> RevokeLifecycle([FromBody] KaevoLifecycleOwnerRequest request, [FromHeader(Name = "X-Kaevo-Admin-Action")] string action, CancellationToken token) =>
        RunLifecycleOwnerAction(request, action, (uri, owner, _) => _lifecycleClient.RevokeAsync(uri, owner, token));

    [Authorize(Policy = "RequiresElevation")]
    [HttpPost("cloud/lifecycle/unpair")]
    public Task<ActionResult<KaevoLifecycleResponse>> UnpairLifecycle([FromBody] KaevoLifecycleOwnerRequest request, [FromHeader(Name = "X-Kaevo-Admin-Action")] string action, CancellationToken token) =>
        RunLifecycleOwnerAction(request, action, (uri, owner, _) => _lifecycleClient.UnpairAsync(uri, owner, token));

    private async Task<ActionResult<KaevoLifecycleResponse>> RunLifecycleOwnerAction(
        KaevoLifecycleOwnerRequest request,
        string action,
        Func<Uri, string, string, Task<KaevoLifecycleResult>> operation)
    {
        var baseUrl = KaevoPlugin.Instance?.Configuration.CloudBaseUrl ?? string.Empty;
        if (!ValidAdminAction(action) || !ValidOwnerToken(request.OwnerAccessToken) || !TryCloudUri(baseUrl, out var cloud))
        {
            return BadRequest(new KaevoLifecycleResponse("invalid", 0));
        }
        var profileId = KaevoPlugin.Instance?.Configuration.ProfileId ?? string.Empty;
        if (string.IsNullOrWhiteSpace(profileId)) return BadRequest(new KaevoLifecycleResponse("invalid", 0));
        var result = await operation(cloud, request.OwnerAccessToken, profileId).ConfigureAwait(false);
        _cloudState.SignalConfigurationChanged();
        return Ok(new KaevoLifecycleResponse(result.State, result.CredentialVersion));
    }

    private static bool ValidAdminAction(string value) => string.Equals(value, "lifecycle", StringComparison.Ordinal);
    private static bool ValidOwnerToken(string value) => !string.IsNullOrWhiteSpace(value) && value.Length <= 8192 && !value.Any(char.IsWhiteSpace);
    private static bool TryCloudUri(string value, out Uri uri) => KaevoCloudEndpointPolicy.TryNormalize(value, out uri);

    [Authorize(Policy = "RequiresElevation")]
    [HttpGet("providers/status")]
    public async Task<ActionResult<IReadOnlyList<KaevoProviderStatusResponse>>> GetProviderStatus(
        CancellationToken cancellationToken)
    {
        var secrets = await _secretStore.ReadAsync(cancellationToken).ConfigureAwait(false);
        var response = SupportedProviders.Select(entry =>
        {
            var provider = secrets?.GetProvider(entry.Key);
            var configured = provider is not null
                && !string.IsNullOrWhiteSpace(provider.BaseUrl)
                && (!entry.Value.RequiresApiKey || !string.IsNullOrWhiteSpace(provider.ApiKey));
            return new KaevoProviderStatusResponse(
                entry.Key,
                entry.Value.DisplayName,
                provider?.Enabled == true,
                configured,
                provider?.BaseUrl ?? string.Empty,
                entry.Value.RequiresApiKey);
        }).ToArray();
        return Ok(response);
    }

    [Authorize(Policy = "RequiresElevation")]
    [HttpPost("providers/{providerName}")]
    public async Task<ActionResult<KaevoProviderProvisionResponse>> ProvisionProvider(
        string providerName,
        [FromBody] KaevoProviderProvisionRequest request,
        CancellationToken cancellationToken)
    {
        var provider = providerName.Trim().ToLowerInvariant();
        if (!SupportedProviders.TryGetValue(provider, out var definition))
        {
            return NotFound(new KaevoProviderProvisionResponse("unsupported", provider));
        }

        var existing = await _secretStore.ReadAsync(cancellationToken).ConfigureAwait(false)
            ?? new KaevoConnectorSecrets(string.Empty, string.Empty, string.Empty);
        var current = existing.GetProvider(provider);
        var baseUrl = request.BaseUrl?.Trim().TrimEnd('/') ?? string.Empty;
        var apiKey = string.IsNullOrWhiteSpace(request.ApiKey) ? current?.ApiKey ?? string.Empty : request.ApiKey.Trim();
        KaevoApprovedDestination? approved = null;
        try
        {
            if (request.Enabled)
            {
                if (definition.RequiresApiKey && string.IsNullOrWhiteSpace(apiKey))
                {
                    throw new ArgumentException("providerCredentialRequired");
                }
                approved = await _providerPolicy.ApproveAsync(provider, baseUrl, cancellationToken).ConfigureAwait(false);
                baseUrl = approved.BaseUri.ToString().TrimEnd('/');
            }
        }
        catch (ArgumentException)
        {
            await _providerAudit.RecordAsync(provider, "denied", "prohibited", null, "invalid", cancellationToken).ConfigureAwait(false);
            return BadRequest(new KaevoProviderProvisionResponse("invalid", provider));
        }

        var providers = existing.Providers is null
            ? new Dictionary<string, KaevoLocalProviderSecret>(StringComparer.OrdinalIgnoreCase)
            : new Dictionary<string, KaevoLocalProviderSecret>(existing.Providers, StringComparer.OrdinalIgnoreCase);
        providers[provider] = new KaevoLocalProviderSecret(
            baseUrl,
            apiKey,
            request.Enabled,
            approved?.Addresses ?? current?.ApprovedAddresses,
            approved?.SecurityClass ?? current?.DestinationClass ?? "private");
        await _secretStore.WriteAsync(
            existing with
            {
                // Preserve the legacy fields until every installed plugin has
                // migrated its protected secret file.
                SonarrBaseUrl = provider == "sonarr" ? baseUrl : existing.SonarrBaseUrl,
                SonarrApiKey = provider == "sonarr" ? apiKey : existing.SonarrApiKey,
                Providers = providers
            },
            cancellationToken).ConfigureAwait(false);
        await _providerAudit.RecordAsync(
            provider,
            "approved",
            approved?.SecurityClass ?? current?.DestinationClass ?? "private",
            approved?.BaseUri,
            "approved",
            cancellationToken).ConfigureAwait(false);
        return Ok(new KaevoProviderProvisionResponse(request.Enabled ? "ready" : "disabled", provider));
    }

    [HttpGet("media-scan")]
    public ActionResult<KaevoMediaScanResponse> GetMediaScan()
    {
        return Ok(new KaevoMediaScanResponse(
            _libraryManager.GetVirtualFolders().Count,
            Count(BaseItemKind.Movie),
            Count(BaseItemKind.Series),
            Count(BaseItemKind.BoxSet)));
    }

    [HttpGet("main-snapshot")]
    public ActionResult<KaevoMainSnapshotResponse> GetMainSnapshot()
    {
        var limit = Math.Clamp(
            KaevoPlugin.Instance?.Configuration.SnapshotItemLimit ?? DefaultItemLimit,
            1,
            MaximumItemLimit);

        var libraries = _libraryManager.GetVirtualFolders()
            .Select(folder => new KaevoLibraryMetadata(
                folder.ItemId.ToString(),
                folder.Name,
                folder.CollectionType?.ToString()))
            .ToArray();

        var response = new KaevoMainSnapshotResponse(
            DateTimeOffset.UtcNow,
            limit,
            libraries,
            QueryMetadata(BaseItemKind.Movie, limit),
            QueryMetadata(BaseItemKind.Series, limit),
            QueryMetadata(BaseItemKind.BoxSet, limit),
            QueryContinueWatching(limit));

        return Ok(response);
    }

    private int Count(BaseItemKind kind)
    {
        return _libraryManager.GetCount(new InternalItemsQuery
        {
            Recursive = true,
            IncludeItemTypes = new[] { kind }
        });
    }

    private IReadOnlyList<KaevoItemMetadata> QueryMetadata(BaseItemKind kind, int limit)
    {
        return QueryMetadata(new InternalItemsQuery
        {
            Recursive = true,
            Limit = limit,
            IncludeItemTypes = new[] { kind }
        });
    }

    private IReadOnlyList<KaevoItemMetadata> QueryContinueWatching(int limit)
    {
        try
        {
            // Jellyfin moved User between assemblies in 10.11. Resolve the active
            // runtime type without binding this net8.0 plugin to the old type.
            var users = _userManager.GetType().GetProperty("Users")?.GetValue(_userManager) as IEnumerable;
            var user = users?.Cast<object>().FirstOrDefault();
            if (user is null)
            {
                return Array.Empty<KaevoItemMetadata>();
            }

            var constructor = typeof(InternalItemsQuery).GetConstructors()
                .FirstOrDefault(candidate =>
                {
                    var parameters = candidate.GetParameters();
                    return parameters.Length == 1 && parameters[0].ParameterType.IsInstanceOfType(user);
                });

            if (constructor?.Invoke(new[] { user }) is not InternalItemsQuery query)
            {
                return Array.Empty<KaevoItemMetadata>();
            }

            query.Recursive = true;
            query.Limit = limit;
            query.IsResumable = true;
            query.IncludeItemTypes = new[] { BaseItemKind.Movie, BaseItemKind.Episode };
            return QueryMetadata(query);
        }
        catch (Exception)
        {
            // Continue Watching is optional. A Jellyfin API change must not make
            // the rest of the bounded snapshot unavailable.
            return Array.Empty<KaevoItemMetadata>();
        }
    }

    private IReadOnlyList<KaevoItemMetadata> QueryMetadata(InternalItemsQuery query)
    {
        // Jellyfin 10.11 changed GetItemList's return contract from List<BaseItem>
        // to IReadOnlyList<BaseItem>. Resolve the runtime method so this net8.0
        // compatibility build does not bind to the obsolete return signature.
        var method = _libraryManager.GetType()
            .GetMethods()
            .FirstOrDefault(candidate =>
                candidate.Name == "GetItemList"
                && candidate.GetParameters().Length == 1
                && candidate.GetParameters()[0].ParameterType.IsInstanceOfType(query));

        if (method?.Invoke(_libraryManager, new object[] { query }) is not IEnumerable items)
        {
            return Array.Empty<KaevoItemMetadata>();
        }

        return items.Cast<object>()
            .OfType<BaseItem>()
            .Select(ToMetadata)
            .ToArray();
    }

    private KaevoItemMetadata ToMetadata(BaseItem item)
    {
        var imageTags = item.ImageInfos
            .GroupBy(image => image.Type)
            .ToDictionary(
                group => group.Key.ToString(),
                group => _imageProcessor.GetImageCacheTag(item, group.First()));

        return new KaevoItemMetadata(
            item.Id.ToString("N"),
            item.Name,
            item.GetBaseItemKind().ToString(),
            item.ProductionYear,
            imageTags);
    }
}
