using Jellyfin.Data.Entities;
using Jellyfin.Data.Enums;
using MediaBrowser.Controller.Dto;
using MediaBrowser.Controller.Entities;
using MediaBrowser.Controller.Library;
using MediaBrowser.Model.Dto;
using MediaBrowser.Model.Entities;
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
    private readonly IDtoService _dtoService;

    public KaevoController(
        ILibraryManager libraryManager,
        IUserManager userManager,
        IDtoService dtoService)
    {
        _libraryManager = libraryManager;
        _userManager = userManager;
        _dtoService = dtoService;
    }

    [HttpGet("status")]
    public ActionResult<KaevoStatusResponse> GetStatus()
    {
        return Ok(new KaevoStatusResponse("ok", "Kaevo", "0.1.0", false));
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

        var user = _userManager.Users.FirstOrDefault();
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
            QueryMetadata(BaseItemKind.Movie, limit, null),
            QueryMetadata(BaseItemKind.Series, limit, null),
            QueryMetadata(BaseItemKind.BoxSet, limit, null),
            user is null ? Array.Empty<KaevoItemMetadata>() : QueryContinueWatching(user, limit));

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

    private IReadOnlyList<KaevoItemMetadata> QueryMetadata(BaseItemKind kind, int limit, User? user)
    {
        return QueryMetadata(new InternalItemsQuery(user)
        {
            Recursive = true,
            Limit = limit,
            IncludeItemTypes = new[] { kind }
        }, user);
    }

    private IReadOnlyList<KaevoItemMetadata> QueryContinueWatching(User user, int limit)
    {
        return QueryMetadata(new InternalItemsQuery(user)
        {
            Recursive = true,
            Limit = limit,
            IsResumable = true,
            IncludeItemTypes = new[] { BaseItemKind.Movie, BaseItemKind.Episode }
        }, user);
    }

    private IReadOnlyList<KaevoItemMetadata> QueryMetadata(InternalItemsQuery query, User? user)
    {
        var dtoOptions = new DtoOptions
        {
            EnableImages = true,
            ImageTypeLimit = 1
        };

        return _libraryManager.GetItemList(query)
            .Select(item => ToMetadata(item, dtoOptions, user))
            .ToArray();
    }

    private KaevoItemMetadata ToMetadata(BaseItem item, DtoOptions dtoOptions, User? user)
    {
        BaseItemDto dto = _dtoService.GetBaseItemDto(item, dtoOptions, user, item);
        var imageTags = dto.ImageTags?.ToDictionary(
            pair => pair.Key.ToString(),
            pair => pair.Value) ?? new Dictionary<string, string>();

        return new KaevoItemMetadata(
            item.Id.ToString("N"),
            item.Name,
            item.GetBaseItemKind().ToString(),
            item.ProductionYear,
            imageTags);
    }
}
