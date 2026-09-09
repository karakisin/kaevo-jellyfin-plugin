using System.Net.Http.Json;
using System.Text.Json;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

// Memory-only exchange for the development notification identity. No ADC,
// password, refresh-token storage, user session or provider credential access.
internal sealed class FirebaseControlAdmission
{
    internal bool ActivationAllowed { get; init; }
    internal required string Channel { get; init; }
    internal required string Epoch { get; init; }
    internal required string CustomToken { get; init; }
    internal required string PushUid { get; init; }
    internal required DateTimeOffset ExpiresAt { get; init; }
    public override string ToString() => "Firebase control admission (redacted)";

    internal static FirebaseControlAdmission Parse(JsonElement value)
    {
        try
        {
            FirebaseControlTokenExchange.UniqueObject(value);
            var expected = new HashSet<string>(["state", "connector_control_protocol", "connector_control_transport",
                "project_id", "connection_id", "epoch", "expires_at", "custom_token", "activation_allowed"]);
            if (!expected.SetEquals(value.EnumerateObject().Select(p => p.Name))
                || value.GetProperty("state").GetString() != "issued"
                || value.GetProperty("connector_control_protocol").GetInt32() != 2
                || value.GetProperty("connector_control_transport").GetString() != "firestore-signals-v1"
                || value.GetProperty("project_id").GetString() != FirebaseFirestoreControlListener.DevelopmentProject
                || value.GetProperty("activation_allowed").ValueKind is not (JsonValueKind.True or JsonValueKind.False))
                throw new InvalidOperationException();
            var channel = value.GetProperty("connection_id").GetString()!;
            var epoch = value.GetProperty("epoch").GetString()!;
            var custom = value.GetProperty("custom_token").GetString()!;
            var expiry = DateTimeOffset.FromUnixTimeSeconds(value.GetProperty("expires_at").GetInt64());
            using var payload = FirebaseControlTokenExchange.Payload(custom);
            var uid = payload.RootElement.GetProperty("uid").GetString()!;
            if (!uid.StartsWith("connector-push-", StringComparison.Ordinal)
                || !FirebaseFirestoreControlListener.IsOpaque(uid[15..], 43)) throw new InvalidOperationException();
            var admission = new FirebaseControlAdmission { Channel = channel, Epoch = epoch,
                CustomToken = custom, PushUid = uid, ExpiresAt = expiry,
                ActivationAllowed = value.GetProperty("activation_allowed").GetBoolean() };
            admission.Check();
            FirebaseControlTokenExchange.CheckClaims(payload.RootElement.GetProperty("claims"), admission);
            return admission;
        }
        catch (Exception) { throw new InvalidOperationException("firebaseControlAdmissionInvalid"); }
    }

    internal void Check()
    {
        if (Channel is null || Epoch is null || !FirebaseFirestoreControlListener.IsOpaque(Channel, 43)
            || !FirebaseFirestoreControlListener.IsOpaque(Epoch, 32)
            || ExpiresAt <= DateTimeOffset.UtcNow || ExpiresAt > DateTimeOffset.UtcNow.AddSeconds(300))
            throw new InvalidOperationException("firebaseControlAdmissionInvalid");
    }
}

internal static class FirebaseControlTokenExchange
{
    private const string Endpoint = "https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken";
    internal static HttpClient CreateClient() => new(new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false })
        { Timeout = TimeSpan.FromSeconds(10) };

    internal static async Task<string> ExchangeAsync(HttpClient http, string apiKey,
        FirebaseControlAdmission admission, CancellationToken cancellationToken)
    {
        admission.Check();
        if (apiKey is null || apiKey.Length is < 1 or > 256
            || apiKey.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('-' or '_')))
            throw new InvalidOperationException("firebaseControlApiKeyInvalid");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(Math.Max(0, Math.Min(10, (admission.ExpiresAt - DateTimeOffset.UtcNow).TotalSeconds))));
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, Endpoint);
            request.Headers.Add("X-Goog-Api-Key", apiKey); // Not in URL or diagnostics.
            request.Content = JsonContent.Create(new { token = admission.CustomToken, returnSecureToken = true });
            using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode) throw new InvalidOperationException();
            if (response.Content.Headers.ContentLength is > 16384) throw new InvalidOperationException();
            await using var stream = await response.Content.ReadAsStreamAsync(deadline.Token).ConfigureAwait(false);
            var bytes = new byte[16385]; var size = 0;
            while (size < bytes.Length)
            {
                var read = await stream.ReadAsync(bytes.AsMemory(size), deadline.Token).ConfigureAwait(false);
                if (read == 0) break;
                size += read;
            }
            if (size == bytes.Length) throw new InvalidOperationException();
            using var body = JsonDocument.Parse(bytes.AsMemory(0, size), new JsonDocumentOptions { MaxDepth = 8 });
            UniqueObject(body.RootElement);
            var token = body.RootElement.GetProperty("idToken").GetString()!;
            if (!int.TryParse(body.RootElement.GetProperty("expiresIn").GetString(), out var seconds) || seconds is < 1 or > 3600)
                throw new InvalidOperationException();
            using var payload = Payload(token);
            var claims = payload.RootElement;
            var project = FirebaseFirestoreControlListener.DevelopmentProject;
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (claims.GetProperty("aud").GetString() != project
                || claims.GetProperty("iss").GetString() != "https://securetoken.google.com/" + project
                || claims.GetProperty("sub").GetString() != admission.PushUid
                || claims.GetProperty("exp").GetInt64() < admission.ExpiresAt.ToUnixTimeSeconds()
                || claims.GetProperty("exp").GetInt64() > now + 3600
                || claims.GetProperty("iat").GetInt64() > now + 30)
                throw new InvalidOperationException();
            CheckClaims(claims, admission);
            admission.Check();
            // HTTPS Auth exchange is the source of this response; this decoding
            // is scope validation, not local signature verification. Firestore
            // verifies the ID token cryptographically and enforces its lease.
            // Deliberately ignore refreshToken; renewal needs fresh signed admission.
            return token;
        }
        catch (Exception)
        {
            cancellationToken.ThrowIfCancellationRequested();
            throw new InvalidOperationException("firebaseControlTokenExchangeFailed");
        }
    }

    internal static JsonDocument Payload(string token)
    {
        if (token is null || token.Length is < 1 or > 7000
            || token.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('-' or '_' or '.')))
            throw new InvalidOperationException();
        var parts = token.Split('.');
        if (parts.Length != 3 || parts.Any(string.IsNullOrEmpty)) throw new InvalidOperationException();
        var encoded = parts[1].Replace('-', '+').Replace('_', '/');
        encoded = encoded.PadRight((encoded.Length + 3) / 4 * 4, '=');
        var document = JsonDocument.Parse(Convert.FromBase64String(encoded), new JsonDocumentOptions { MaxDepth = 8 });
        try { UniqueObject(document.RootElement); return document; }
        catch { document.Dispose(); throw; }
    }

    internal static void UniqueObject(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.Object) throw new InvalidOperationException();
        var names = new HashSet<string>(StringComparer.Ordinal);
        if (value.EnumerateObject().Any(p => !names.Add(p.Name))) throw new InvalidOperationException();
    }

    internal static void CheckClaims(JsonElement value, FirebaseControlAdmission admission)
    {
        UniqueObject(value);
        if (value.GetProperty("kaevo_purpose").GetString() != "connector_push"
            || value.GetProperty("kaevo_environment").GetString() != "development-preview"
            || value.GetProperty("kaevo_transport").GetString() != "firestore-signals-v1"
            || value.GetProperty("kaevo_channel").GetString() != admission.Channel
            || value.GetProperty("kaevo_epoch").GetString() != admission.Epoch) throw new InvalidOperationException();
    }
}
