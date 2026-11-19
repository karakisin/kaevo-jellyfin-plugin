using Kaevo.Plugin.KaevoForJellyfin.Services;
using MediaBrowser.Controller;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Kaevo.Plugin.KaevoForJellyfin.Api;

[ApiController]
[Authorize(Policy = "RequiresElevation")]
[Route("kaevo/items/{itemId}/trickplay")]
public sealed class KaevoTrickplayController : ControllerBase
{
    private readonly KaevoTrickplayGeneration _generation;
    private readonly IServerApplicationHost _host;
    public KaevoTrickplayController(KaevoTrickplayGeneration generation, IServerApplicationHost host)
    { _generation = generation; _host = host; }

    [HttpPost]
    public IActionResult Generate(string itemId, [FromQuery] string serverId)
    {
        if (KaevoPlugin.Instance?.PackageIntegrityValid != true) return StatusCode(503);
        if (!MatchesServer(serverId, _host.SystemId)) return Conflict(new { error = "trickplayServerChanged" });
        try { return Accepted(_generation.Queue(itemId)); }
        catch (InvalidOperationException error) { return BadRequest(new { error = error.Message }); }
    }

    [HttpGet]
    public IActionResult Status(string itemId, [FromQuery] string serverId)
    {
        if (KaevoPlugin.Instance?.PackageIntegrityValid != true) return StatusCode(503);
        if (!MatchesServer(serverId, _host.SystemId)) return Conflict(new { error = "trickplayServerChanged" });
        try { return Ok(_generation.Status(itemId)); }
        catch (InvalidOperationException error) { return BadRequest(new { error = error.Message }); }
    }

    internal static bool MatchesServer(string? expected, string actual) =>
        !string.IsNullOrWhiteSpace(expected) && string.Equals(expected, actual, StringComparison.Ordinal);
}
