using System.Collections;
using Jellyfin.Data.Enums;
using MediaBrowser.Controller.Drawing;
using MediaBrowser.Controller.Entities;
using MediaBrowser.Controller.Library;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Kaevo.Plugin.KaevoForJellyfin.Models;
using Kaevo.Plugin.KaevoForJellyfin.Services;

namespace Kaevo.Plugin.KaevoForJellyfin.Api;

[ApiController]
[Route("kaevo")]
[Produces("application/json")]
public sealed class KaevoController : ControllerBase
{
    private const int DefaultItemLimit = 50;
    private const int MaximumItemLimit = 100;
    private readonly ILibraryManager _libraryManager;
    private readonly IUserManager _userManager;
    private readonly IImageProcessor _imageProcessor;
    private readonly KaevoCloudState _cloudState;
    private readonly KaevoSecretStore _secretStore;

    public KaevoController(
        ILibraryManager libraryManager,
        IUserManager userManager,
        IImageProcessor imageProcessor,
        KaevoCloudState cloudState,
        KaevoSecretStore secretStore)
    {
        _libraryManager = libraryManager;
        _userManager = userManager;
        _imageProcessor = imageProcessor;
        _cloudState = cloudState;
        _secretStore = secretStore;
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
            "0.2.5",
            configuration.CloudConnectorEnabled,
            cloud.Status,
            cloud.LastHeartbeatUtc,
            configuration.RemoteMetadataEnabled,
            configuration.RemoteWritesEnabled,
            configuration.RemotePlaybackEnabled,
            relay.Status,
            relay.LastConnectedUtc,
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
    [HttpPost("cloud/activate")]
    public async Task<ActionResult<KaevoCloudActivationResponse>> ActivateCloud(
        [FromBody] KaevoCloudActivationRequest request,
        CancellationToken cancellationToken)
    {
        KaevoValidatedCloudActivation activation;
        try
        {
            activation = KaevoCloudActivationValidator.Validate(request);
        }
        catch (ArgumentException exception)
        {
            return BadRequest(new KaevoCloudActivationResponse("invalid", exception.Message));
        }

        // Persist the Jellyfin credential only in the plugin's owner-only secret
        // file. It is never copied into plugin configuration, logs, or responses.
        await _secretStore.WriteAsync(
            new KaevoConnectorSecrets(string.Empty, string.Empty, activation.JellyfinAccessToken),
            cancellationToken).ConfigureAwait(false);

        var configuration = KaevoPlugin.Instance?.Configuration;
        if (configuration is null)
        {
            return StatusCode(503, new KaevoCloudActivationResponse("unavailable", "pluginUnavailable"));
        }

        configuration.CloudBaseUrl = activation.CloudBaseUrl;
        configuration.ProfileId = activation.ProfileId;
        configuration.ConnectorId = activation.ConnectorId;
        configuration.PairingCode = activation.PairingCode;
        configuration.LocalJellyfinBaseUrl = "http://127.0.0.1:8096";
        configuration.JellyfinUserId = activation.JellyfinUserId;
        configuration.CloudConnectorEnabled = true;
        configuration.RemoteMetadataEnabled = true;
        configuration.RemoteArtworkEnabled = true;
        configuration.RemoteWritesEnabled = false;
        configuration.RemotePlaybackEnabled = false;
        configuration.OptimizerExecutionEnabled = false;
        KaevoPlugin.Instance?.SaveConfiguration();
        _cloudState.Set("connecting");

        return Accepted(new KaevoCloudActivationResponse(
            "connecting",
            "Remote access is being prepared."));
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
