using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Kaevo.Plugin.KaevoForJellyfin.Models;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

public sealed class KaevoSeerrIdentityProvisioningService
{
    private const int Administrator = 2;
    private const int ManageUsers = 8;
    private const int ManageRequests = 16;
    private const int Request = 32;
    private const int Request4K = 1_024;
    private const int Request4KMovie = 2_048;
    private const int Request4KTelevision = 4_096;
    private const int RequestMovie = 262_144;
    private const int RequestTelevision = 524_288;
    private const int ManagementMask = Administrator | ManageUsers | ManageRequests;
    private const int RequestMask = Request | Request4K | Request4KMovie | Request4KTelevision | RequestMovie | RequestTelevision;
    private const int MaximumResponseBytes = 1_000_000;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly KaevoProviderTransport? _transport;
    private readonly Func<KaevoConnectorSecrets, HttpMethod, string, object?, CancellationToken, Task<ProviderResponse>>? _sendOverride;

    public KaevoSeerrIdentityProvisioningService(KaevoProviderTransport transport)
    {
        _transport = transport;
    }

    internal KaevoSeerrIdentityProvisioningService(
        Func<KaevoConnectorSecrets, HttpMethod, string, object?, CancellationToken, Task<ProviderResponse>> sendOverride)
    {
        _sendOverride = sendOverride;
    }

    internal sealed record ProviderResponse(int StatusCode, JsonElement Body);
    internal sealed record SeerrUser(int Id, string JellyfinUserId, int Permissions);

    public static bool IsSafeRequestPermissionMask(int permissions) =>
        permissions >= 0 && (permissions & ~RequestMask) == 0;

    public async Task<KaevoSeerrJellyfinUserProvisionResponse> EnsureJellyfinUserAccessAsync(
        KaevoConnectorSecrets secrets,
        string jellyfinUserId,
        int requestedPermissions,
        CancellationToken cancellationToken)
    {
        if (!KaevoProfileJellyfinBindingStore.TryNormalizeJellyfinUserId(jellyfinUserId, out var normalizedUserId)
            || !IsSafeRequestPermissionMask(requestedPermissions))
        {
            return new("invalid");
        }

        try
        {
            var users = await ReadUsersAsync(secrets, cancellationToken).ConfigureAwait(false);
            var matches = users.Where(user => user.JellyfinUserId == normalizedUserId).ToArray();
            if (matches.Length > 1) return new("seerr_user_ambiguous");

            var createdByThisAttempt = false;
            var user = matches.SingleOrDefault();
            if (user is null)
            {
                try
                {
                    var imported = await SendAsync(
                        secrets,
                        HttpMethod.Post,
                        "/api/v1/user/import-from-jellyfin",
                        new { jellyfinUserIds = new[] { normalizedUserId } },
                        cancellationToken).ConfigureAwait(false);
                    user = ParseUsers(imported.Body)
                        .SingleOrDefault(candidate => candidate.JellyfinUserId == normalizedUserId);
                }
                catch
                {
                    // Seerr can report a conflict while its user index catches
                    // up. The exact read-back below is authoritative.
                }

                for (var attempt = 0; user is null && attempt < 3; attempt++)
                {
                    if (attempt > 0)
                    {
                        await Task.Delay(TimeSpan.FromMilliseconds(300), cancellationToken).ConfigureAwait(false);
                    }
                    var refreshed = await ReadUsersAsync(secrets, cancellationToken).ConfigureAwait(false);
                    var refreshedMatches = refreshed
                        .Where(candidate => candidate.JellyfinUserId == normalizedUserId)
                        .ToArray();
                    if (refreshedMatches.Length > 1) return new("seerr_user_ambiguous");
                    user = refreshedMatches.SingleOrDefault();
                }
                createdByThisAttempt = user is not null;
            }

            if (user is null) return new("seerr_import_failed");

            var detail = await SendAsync(
                secrets,
                HttpMethod.Get,
                $"/api/v1/user/{user.Id}",
                null,
                cancellationToken).ConfigureAwait(false);
            var exact = ParseSingleUser(detail.Body);
            if (exact is null || exact.JellyfinUserId != normalizedUserId)
            {
                if (createdByThisAttempt) await BestEffortDeleteAsync(secrets, user.Id, cancellationToken).ConfigureAwait(false);
                return new("seerr_identity_mismatch");
            }

            // Never repurpose or downgrade an existing privileged Seerr
            // identity. Imported users can inherit unsafe defaults from Seerr,
            // so only the identity created by this exact attempt may have those
            // defaults removed before its request-only permissions are saved.
            if (!createdByThisAttempt && (exact.Permissions & ManagementMask) != 0)
            {
                return new("seerr_user_privileged");
            }

            var targetPermissions = ((exact.Permissions & ~RequestMask) | requestedPermissions) & ~ManagementMask;
            await SendAsync(
                secrets,
                HttpMethod.Put,
                $"/api/v1/user/{exact.Id}",
                new { permissions = targetPermissions },
                cancellationToken).ConfigureAwait(false);

            var verifiedResponse = await SendAsync(
                secrets,
                HttpMethod.Get,
                $"/api/v1/user/{exact.Id}",
                null,
                cancellationToken).ConfigureAwait(false);
            var verified = ParseSingleUser(verifiedResponse.Body);
            if (verified is null
                || verified.JellyfinUserId != normalizedUserId
                || (verified.Permissions & requestedPermissions) != requestedPermissions
                || (verified.Permissions & ManagementMask) != 0)
            {
                if (createdByThisAttempt) await BestEffortDeleteAsync(secrets, exact.Id, cancellationToken).ConfigureAwait(false);
                return new("seerr_permission_failed");
            }

            return new("ready", verified.Id);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return new("provider_unavailable");
        }
    }

    /// <summary>
    /// Deletes only the Seerr user whose immutable Jellyfin identity and Seerr
    /// identifier both match the caller's verified binding.  A successful
    /// DELETE response is not sufficient: the subsequent authoritative user
    /// list must contain neither identifier before deletion is reported.
    /// </summary>
    public async Task<KaevoSeerrJellyfinUserDeletionResponse> DeleteExactJellyfinUserAsync(
        KaevoConnectorSecrets secrets,
        string jellyfinUserId,
        int seerrUserId,
        CancellationToken cancellationToken)
    {
        if (!KaevoProfileJellyfinBindingStore.TryNormalizeJellyfinUserId(jellyfinUserId, out var normalizedUserId)
            || seerrUserId <= 0)
        {
            return new("invalid");
        }

        try
        {
            var users = await ReadUsersAsync(secrets, cancellationToken).ConfigureAwait(false);
            var exactMatches = users
                .Where(user => user.Id == seerrUserId && user.JellyfinUserId == normalizedUserId)
                .ToArray();
            if (exactMatches.Length != 1) return new("seerr_identity_mismatch");

            // Refuse an ambiguous relationship even if one row happens to
            // match the requested Seerr ID.  Deletion must have one exact,
            // immutable provider edge.
            if (users.Count(user => user.JellyfinUserId == normalizedUserId) != 1)
            {
                return new("seerr_user_ambiguous");
            }

            await SendAsync(
                secrets,
                HttpMethod.Delete,
                $"/api/v1/user/{seerrUserId}",
                null,
                cancellationToken).ConfigureAwait(false);

            for (var attempt = 0; attempt < 3; attempt++)
            {
                if (attempt > 0)
                {
                    await Task.Delay(TimeSpan.FromMilliseconds(350), cancellationToken).ConfigureAwait(false);
                }
                var readback = await ReadUsersAsync(secrets, cancellationToken).ConfigureAwait(false);
                var targetStillExists = readback.Any(user =>
                    user.Id == seerrUserId || user.JellyfinUserId == normalizedUserId);
                if (!targetStillExists) return new("deleted");
            }

            return new("seerr_delete_unconfirmed");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return new("provider_unavailable");
        }
    }

    private async Task<IReadOnlyList<SeerrUser>> ReadUsersAsync(
        KaevoConnectorSecrets secrets,
        CancellationToken cancellationToken)
    {
        var response = await SendAsync(
            secrets,
            HttpMethod.Get,
            "/api/v1/user",
            null,
            cancellationToken).ConfigureAwait(false);
        return ParseUsers(response.Body);
    }

    private async Task BestEffortDeleteAsync(
        KaevoConnectorSecrets secrets,
        int userId,
        CancellationToken cancellationToken)
    {
        try
        {
            await SendAsync(
                secrets,
                HttpMethod.Delete,
                $"/api/v1/user/{userId}",
                null,
                cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            // The caller receives a bounded failure state. Cleanup remains
            // retryable through the explicit profile-deletion workflow.
        }
    }

    private Task<ProviderResponse> SendAsync(
        KaevoConnectorSecrets secrets,
        HttpMethod method,
        string path,
        object? body,
        CancellationToken cancellationToken) =>
        _sendOverride is not null
            ? _sendOverride(secrets, method, path, body, cancellationToken)
            : SendProviderAsync(secrets, method, path, body, cancellationToken);

    private async Task<ProviderResponse> SendProviderAsync(
        KaevoConnectorSecrets secrets,
        HttpMethod method,
        string path,
        object? body,
        CancellationToken cancellationToken)
    {
        var seerr = secrets.GetProvider("seerr");
        if (seerr?.Enabled != true
            || !Uri.TryCreate(seerr.BaseUrl, UriKind.Absolute, out _)
            || string.IsNullOrWhiteSpace(seerr.ApiKey)
            || _transport is null)
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

        using var response = await _transport.SendAsync(
            "seerr",
            seerr,
            message,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken).ConfigureAwait(false);
        if ((int)response.StatusCode is >= 300 and < 400)
        {
            throw new InvalidOperationException("seerrRedirectRejected");
        }
        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException("seerrRequestRejected");
        }
        if (method == HttpMethod.Delete || response.Content.Headers.ContentLength == 0)
        {
            return new((int)response.StatusCode, JsonSerializer.SerializeToElement(new { ok = true }, JsonOptions));
        }

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var memory = new MemoryStream();
        var buffer = new byte[16_384];
        while (true)
        {
            var count = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (count == 0) break;
            if (memory.Length + count > MaximumResponseBytes)
            {
                throw new InvalidOperationException("seerrResponseTooLarge");
            }
            await memory.WriteAsync(buffer.AsMemory(0, count), cancellationToken).ConfigureAwait(false);
        }
        using var document = JsonDocument.Parse(memory.ToArray());
        return new((int)response.StatusCode, document.RootElement.Clone());
    }

    internal static IReadOnlyList<SeerrUser> ParseUsers(JsonElement root)
    {
        if (root.ValueKind == JsonValueKind.Array)
        {
            return root.EnumerateArray().Select(ParseSingleUser).Where(static user => user is not null).Cast<SeerrUser>().ToArray();
        }
        if (root.ValueKind != JsonValueKind.Object) return Array.Empty<SeerrUser>();
        foreach (var propertyName in new[] { "results", "users", "createdUsers" })
        {
            if (TryGetProperty(root, propertyName, out var array) && array.ValueKind == JsonValueKind.Array)
            {
                return array.EnumerateArray().Select(ParseSingleUser).Where(static user => user is not null).Cast<SeerrUser>().ToArray();
            }
        }
        var single = ParseSingleUser(root);
        return single is null ? Array.Empty<SeerrUser>() : new[] { single };
    }

    internal static SeerrUser? ParseSingleUser(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.Object
            || !TryGetProperty(value, "id", out var idValue)
            || !idValue.TryGetInt32(out var id)
            || !TryGetProperty(value, "permissions", out var permissionsValue)
            || !permissionsValue.TryGetInt32(out var permissions))
        {
            return null;
        }

        string? jellyfinUserId = null;
        if (TryGetProperty(value, "jellyfinUserId", out var direct) && direct.ValueKind == JsonValueKind.String)
        {
            jellyfinUserId = direct.GetString();
        }
        else if (TryGetProperty(value, "jellyfinUser", out var nested)
                 && nested.ValueKind == JsonValueKind.Object
                 && TryGetProperty(nested, "id", out var nestedId)
                 && nestedId.ValueKind == JsonValueKind.String)
        {
            jellyfinUserId = nestedId.GetString();
        }

        return KaevoProfileJellyfinBindingStore.TryNormalizeJellyfinUserId(jellyfinUserId, out var normalized)
            ? new SeerrUser(id, normalized, permissions)
            : null;
    }

    private static bool TryGetProperty(JsonElement value, string name, out JsonElement property)
    {
        foreach (var candidate in value.EnumerateObject())
        {
            if (string.Equals(candidate.Name, name, StringComparison.OrdinalIgnoreCase))
            {
                property = candidate.Value;
                return true;
            }
        }
        property = default;
        return false;
    }
}
