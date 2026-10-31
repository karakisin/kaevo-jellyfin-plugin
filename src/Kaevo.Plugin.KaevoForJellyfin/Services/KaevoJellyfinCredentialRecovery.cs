using System.Net.Http.Headers;
using System.Text.Json;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

internal sealed class KaevoJellyfinCredentialRecovery
{
    private static readonly HttpClient Client = new(new HttpClientHandler { AllowAutoRedirect = false })
        { Timeout = TimeSpan.FromSeconds(5) };
    private readonly SemaphoreSlim gate = new(1, 1);
    private DateTimeOffset nextAttempt;

    internal async Task<string?> RecoverAsync(Uri baseUri, string serverId, string rejectedKey,
        bool explicitlyConfigured, Func<CancellationToken, Task<string>> existingKey,
        Func<string, CancellationToken, Task<bool>> saveIfStillBound,
        CancellationToken cancellationToken, HttpClient? client = null)
    {
        if (explicitlyConfigured || !Guid.TryParse(serverId, out var expectedId) || expectedId == Guid.Empty
            || baseUri.Scheme is not ("http" or "https") || !string.IsNullOrEmpty(baseUri.UserInfo)) return null;
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (DateTimeOffset.UtcNow < nextAttempt) return null;
            nextAttempt = DateTimeOffset.UtcNow.AddSeconds(30);
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            deadline.CancelAfter(TimeSpan.FromSeconds(6));
            var transport = client ?? Client;
            // Never send the replacement until the unauthenticated endpoint
            // identifies the exact server recorded by verified V3 pairing.
            if (!await MatchesServerAsync(transport, baseUri, "System/Info/Public", expectedId, null, deadline.Token)) return null;
            var key = await existingKey(deadline.Token).WaitAsync(deadline.Token).ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(key) || key == rejectedKey
                || key.Any(c => char.IsControl(c) || char.IsWhiteSpace(c) || c is '"' or '\\')) return null;
            // Also prove that the existing key is accepted; no writes or new keys.
            if (!await MatchesServerAsync(transport, baseUri, "System/Info", expectedId, key, deadline.Token)) return null;
            return await saveIfStillBound(key, deadline.Token).ConfigureAwait(false) ? key : null;
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            // Preserve the original fixed 401 category. Do not leak tokens/URLs.
            return null;
        }
        finally { gate.Release(); }
    }

    private static async Task<bool> MatchesServerAsync(HttpClient client, Uri root, string path,
        Guid expected, string? key, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(root, path));
        if (key is not null)
            request.Headers.Authorization = new AuthenticationHeaderValue("MediaBrowser",
                $"Client=\"Kaevo\", Device=\"Kaevo Jellyfin Plugin\", DeviceId=\"kaevo-plugin\", Version=\"1\", Token=\"{key}\"");
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode) return false;
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var bytes = new MemoryStream();
        var buffer = new byte[4096];
        int count;
        while ((count = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
        {
            if (bytes.Length + count > 65536) return false;
            bytes.Write(buffer, 0, count);
        }
        using var document = JsonDocument.Parse(bytes.ToArray());
        return document.RootElement.TryGetProperty("Id", out var id) && id.ValueKind == JsonValueKind.String
            && Guid.TryParse(id.GetString(), out var actual) && actual == expected;
    }
}
