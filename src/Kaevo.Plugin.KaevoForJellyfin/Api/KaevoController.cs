using System.Collections;
using Jellyfin.Data.Enums;
using MediaBrowser.Controller.Drawing;
using MediaBrowser.Controller.Entities;
using MediaBrowser.Controller.Library;
using Microsoft.AspNetCore.Mvc;
using Kaevo.Plugin.KaevoForJellyfin.Models;

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

    public KaevoController(
        ILibraryManager libraryManager,
        IUserManager userManager,
        IImageProcessor imageProcessor)
    {
        _libraryManager = libraryManager;
        _userManager = userManager;
        _imageProcessor = imageProcessor;
    }

    [HttpGet("status")]
    public ActionResult<KaevoStatusResponse> GetStatus()
    {
        return Ok(new KaevoStatusResponse("ok", "Kaevo", "0.1.1", false));
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
        return _libraryManager.GetItemList(query)
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
