using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

/// Read-only batch eligibility. Account deletion must not remove Seerr users
/// first and only then discover Jellyfin refuses its last user/administrator.
internal static class KaevoAccountDeletionEligibility
{
    internal sealed record Target(string ProfileId, string JellyfinUserId);

    internal static IReadOnlyList<Target> Targets(IReadOnlyDictionary<string, JsonElement> parameters,
        KaevoCloudConnectorService.AccountLifecycleV2CommandContext context)
    {
        if (!parameters.TryGetValue("planned_jellyfin_deletions", out var value)
            || value.ValueKind != JsonValueKind.Array || value.GetArrayLength() is < 1 or > 32)
            throw new InvalidOperationException("accountLifecycleV2DeletionPlanRequired");
        var result = new List<Target>();
        var profiles = new HashSet<string>(StringComparer.Ordinal);
        var users = new HashSet<string>(StringComparer.Ordinal);
        foreach (var entry in value.EnumerateArray())
        {
            if (entry.ValueKind != JsonValueKind.Object || entry.EnumerateObject().Count() != 2
                || !entry.TryGetProperty("profile_id", out var profile) || profile.ValueKind != JsonValueKind.String
                || !entry.TryGetProperty("jellyfin_user_id", out var user) || user.ValueKind != JsonValueKind.String)
                throw new InvalidOperationException("accountLifecycleV2DeletionPlanInvalid");
            var pid = profile.GetString()!;
            var uid = user.GetString()!;
            if (pid.Length is < 1 or > 128 || pid.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '_' or '-' or '.' or ':'))
                || !KaevoProfileJellyfinBindingStore.TryNormalizeJellyfinUserId(uid, out var normalized) || uid != normalized
                || !profiles.Add(pid) || !users.Add(uid))
                throw new InvalidOperationException("accountLifecycleV2DeletionPlanInvalid");
            result.Add(new Target(pid, uid));
        }
        if (!result.Any(t => t.ProfileId == context.ProfileId && t.JellyfinUserId == context.JellyfinUserId))
            throw new InvalidOperationException("accountLifecycleV2DeletionPlanMismatch");
        return result.OrderBy(t => t.ProfileId, StringComparer.Ordinal).ToArray();
    }

    internal static string Check(JsonElement usersPayload, IReadOnlyList<Target> targets,
        Func<string, string?> resolveLocalBinding)
    {
        if (usersPayload.ValueKind != JsonValueKind.Array || usersPayload.GetArrayLength() > 10000
            || targets.Count is < 1 or > 32)
            throw new InvalidOperationException("accountLifecycleV2JellyfinInventoryInvalid");
        var users = new Dictionary<string, bool>(StringComparer.Ordinal);
        foreach (var user in usersPayload.EnumerateArray())
        {
            if (user.ValueKind != JsonValueKind.Object
                || user.EnumerateObject().Select(p => p.Name).Distinct(StringComparer.Ordinal).Count() != user.EnumerateObject().Count()
                || !user.TryGetProperty("Id", out var id) || id.ValueKind != JsonValueKind.String
                || !KaevoProfileJellyfinBindingStore.TryNormalizeJellyfinUserId(id.GetString(), out var uid)
                || !user.TryGetProperty("Policy", out var policy) || policy.ValueKind != JsonValueKind.Object
                || policy.EnumerateObject().Select(p => p.Name).Distinct(StringComparer.Ordinal).Count() != policy.EnumerateObject().Count()
                || !policy.TryGetProperty("IsAdministrator", out var admin)
                || admin.ValueKind is not (JsonValueKind.True or JsonValueKind.False)
                || !users.TryAdd(uid, admin.GetBoolean()))
                throw new InvalidOperationException("accountLifecycleV2JellyfinInventoryInvalid");
        }
        foreach (var target in targets)
        {
            // Earlier users in this exact operation may already be absent.
            // A present user must still match its existing local profile map.
            if (users.ContainsKey(target.JellyfinUserId)
                && resolveLocalBinding(target.ProfileId) != target.JellyfinUserId)
                throw new InvalidOperationException("accountLifecycleV2DeletionPlanBindingChanged");
        }
        var planned = targets.Select(t => t.JellyfinUserId).ToHashSet(StringComparer.Ordinal);
        if (users.Keys.Any(planned.Contains))
        {
            if (!users.Keys.Any(id => !planned.Contains(id)))
                throw new InvalidOperationException("accountLifecycleV2LastJellyfinUser");
            if (users.Any(p => p.Value && planned.Contains(p.Key))
                && !users.Any(p => p.Value && !planned.Contains(p.Key)))
                throw new InvalidOperationException("accountLifecycleV2LastJellyfinAdministrator");
        }
        var canonical = JsonSerializer.Serialize(targets.OrderBy(t => t.ProfileId, StringComparer.Ordinal)
            .Select(t => new { jellyfin_user_id = t.JellyfinUserId, profile_id = t.ProfileId }));
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
    }
}
