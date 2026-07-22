using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Kaevo.Plugin.KaevoForJellyfin.Models;
using Microsoft.Extensions.Logging;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

internal sealed record KaevoPairingV3Start(
    string Protocol, string TicketId, DateTimeOffset ExpiresAtUtc, string PluginInstanceId, string PluginPublicKey,
    string PluginFingerprint, string JellyfinServerId, string JellyfinServerName, string LocalEndpoint,
    string PairingUri, string QrPayloadSignature);

internal sealed record KaevoPairingV3ChallengeResponse(
    string Protocol, string ChallengeId, string ChallengeNonce, DateTimeOffset IssuedAtUtc, DateTimeOffset ExpiresAtUtc,
    string PluginInstanceId, string PluginFingerprint, string JellyfinServerId, string CompletionRoute, string Signature,
    string CorrelationId);

internal sealed record KaevoPairingV3Completion(
    string Protocol, string TicketId, string PairingAttemptId, string ChallengeId, string ChallengeNonce, string ChallengeResponseSignature,
    string Authorization, string JellyfinUserId, string CorrelationId);

internal sealed record KaevoPairingV3CloudResult(string Code, string ConnectorId = "", bool Idempotent = false, bool Retryable = false);

/// <summary>
/// A prepared future connector request. No connector operation is migrated in
/// Phase C; this keeps the signed shape ready without changing heartbeat,
/// revoke, relay-ticket, or legacy lifecycle traffic.
/// </summary>
internal sealed record KaevoPairingV3SignedConnectorRequest(
    string ConnectorId, string PluginKeyId, string Timestamp, string Nonce, string BodyDigest, string Signature);

internal interface IKaevoPairingV3CloudClient
{
    Task<KaevoPairingV3CloudResult> RedeemAsync(Uri cloudBase, KaevoPairingV3RedemptionRequest request, CancellationToken cancellationToken);
    Task<KaevoPairingV3CloudResult> StatusAsync(Uri cloudBase, KaevoPairingV3StatusRequest request, CancellationToken cancellationToken);
}

internal sealed record KaevoPairingV3RedemptionRequest(
    string Authorization, string TicketId, string PairingAttemptId, string PluginInstanceId, string PluginPublicKey,
    string PluginPublicKeyFingerprint, string JellyfinServerId, string JellyfinUserId, string AuthorizationJti,
    string PluginKeyId, string Timestamp, string Nonce, string Signature, string CorrelationId);

internal sealed record KaevoPairingV3StatusRequest(
    string PairingAttemptId, string AuthorizationJti, string PluginInstanceId, string PluginPublicKey,
    string PluginPublicKeyFingerprint, string JellyfinServerId, string Timestamp, string Nonce, string Signature,
    string PluginKeyId, string CorrelationId);

internal sealed class KaevoPairingV3CloudClient : IKaevoPairingV3CloudClient
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly HttpClient _http;

    internal KaevoPairingV3CloudClient() : this(new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(8) }) { }
    internal KaevoPairingV3CloudClient(HttpClient http) => _http = http;

    public Task<KaevoPairingV3CloudResult> RedeemAsync(Uri cloudBase, KaevoPairingV3RedemptionRequest request, CancellationToken cancellationToken) =>
        SendAsync(cloudBase, "/v3/home-connectors/pairing/redemptions", new
        {
            protocol = KaevoPairingV3Crypto.Protocol, authorization = request.Authorization, ticketId = request.TicketId,
            pairingAttemptId = request.PairingAttemptId, pluginInstanceId = request.PluginInstanceId,
            pluginPublicKey = request.PluginPublicKey, pluginPublicKeyFingerprint = request.PluginPublicKeyFingerprint,
            jellyfinServerId = request.JellyfinServerId, jellyfinUserId = request.JellyfinUserId, pluginKeyId = request.PluginKeyId
        }, request.Timestamp, request.Nonce, request.Signature, request.CorrelationId, cancellationToken);

    // Phase B exposes this status route as POST; do not change the deployed Cloud contract in Plugin Phase C.
    public Task<KaevoPairingV3CloudResult> StatusAsync(Uri cloudBase, KaevoPairingV3StatusRequest request, CancellationToken cancellationToken) =>
        SendAsync(cloudBase, "/v3/home-connectors/pairing/attempts/" + Uri.EscapeDataString(request.PairingAttemptId), new
        {
            protocol = KaevoPairingV3Crypto.Protocol, authorizationJti = request.AuthorizationJti,
            pairingAttemptId = request.PairingAttemptId, pluginInstanceId = request.PluginInstanceId,
            pluginPublicKey = request.PluginPublicKey, pluginPublicKeyFingerprint = request.PluginPublicKeyFingerprint,
            jellyfinServerId = request.JellyfinServerId, pluginKeyId = request.PluginKeyId
        }, request.Timestamp, request.Nonce, request.Signature, request.CorrelationId, cancellationToken);

    private async Task<KaevoPairingV3CloudResult> SendAsync(Uri cloudBase, string path, object body, string timestamp, string nonce, string signature, string correlationId, CancellationToken cancellationToken)
    {
        var uri = new Uri(new Uri(cloudBase.ToString().TrimEnd('/') + "/"), path.TrimStart('/'));
        using var message = new HttpRequestMessage(HttpMethod.Post, uri)
        { Content = new StringContent(JsonSerializer.Serialize(body, JsonOptions), Encoding.UTF8, "application/json") };
        message.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        message.Headers.TryAddWithoutValidation("X-Kaevo-Plugin-Timestamp", timestamp);
        message.Headers.TryAddWithoutValidation("X-Kaevo-Plugin-Nonce", nonce);
        message.Headers.TryAddWithoutValidation("X-Kaevo-Plugin-Signature", signature);
        message.Headers.TryAddWithoutValidation("X-Kaevo-Correlation-Id", correlationId);
        try
        {
            using var response = await _http.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
            using var document = JsonDocument.Parse(await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false));
            var root = document.RootElement;
            var code = root.TryGetProperty("code", out var codeValue) ? codeValue.GetString() ?? "unexpected_internal_error" : "cloud_unavailable";
            var connectorId = root.TryGetProperty("connectorId", out var connectorValue) ? connectorValue.GetString() ?? "" : "";
            var idempotent = root.TryGetProperty("idempotent", out var idempotentValue) && idempotentValue.ValueKind == JsonValueKind.True;
            var retryable = root.TryGetProperty("retryable", out var retryableValue) && retryableValue.ValueKind == JsonValueKind.True;
            return new KaevoPairingV3CloudResult(code, connectorId, idempotent, retryable);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { return new KaevoPairingV3CloudResult("ambiguous_enrollment", Retryable: true); }
        catch (HttpRequestException) { return new KaevoPairingV3CloudResult("cloud_unavailable", Retryable: true); }
        catch (JsonException) { return new KaevoPairingV3CloudResult("ambiguous_enrollment", Retryable: true); }
    }
}

public sealed class KaevoPairingV3Service
{
    private const int TicketLifetimeSeconds = 120;
    private const int ChallengeLifetimeSeconds = 30;
    private const int ReservationLifetimeSeconds = 90;
    private readonly KaevoPairingV3Store _store;
    private readonly IKaevoPairingV3CloudClient _cloud;
    private readonly Func<bool> _enabled;
    private readonly Func<string> _verificationKeys;
    private readonly Func<string> _authorizationIssuer;
    private readonly Action<string, string, string, string, int, string> _observe;

    internal KaevoPairingV3Service(KaevoPairingV3Store store, IKaevoPairingV3CloudClient cloud, Func<bool> enabled,
        Func<string> verificationKeys, Func<string>? authorizationIssuer = null, Action<string, string, string, string, int, string>? observe = null)
    {
        _store = store; _cloud = cloud; _enabled = enabled; _verificationKeys = verificationKeys;
        _authorizationIssuer = authorizationIssuer ?? (() => string.Empty);
        _observe = observe ?? ((_, _, _, _, _, _) => { });
    }

    internal static KaevoPairingV3Service ForPlugin(ILogger<KaevoPairingV3Service> logger) => new(KaevoPairingV3Store.ForPlugin(), new KaevoPairingV3CloudClient(),
        () => KaevoPlugin.Instance?.Configuration.PairingV3Enabled == true,
        () => KaevoPlugin.Instance?.Configuration.PairingV3CloudAuthorizationVerificationKeysJson ?? string.Empty,
        () => KaevoPlugin.Instance?.Configuration.PairingV3CloudAuthorizationIssuer ?? string.Empty,
        (correlationId, attemptReference, route, transition, status, outcome) => logger.LogInformation(
            "Kaevo pairing V3 CorrelationId={CorrelationId} PairingAttemptRef={PairingAttemptRef} Route={Route} Transition={Transition} Status={Status} Outcome={Outcome}",
            correlationId, attemptReference, route, transition, status, outcome));

    /// <summary>
    /// Returns only the local pairing state needed by the elevated Jellyfin
    /// configuration page. This is intentionally offline and redacted: a
    /// successful state neither proves Cloud reachability nor reveals a
    /// connector identifier, ticket, authorization, or user/server binding.
    /// </summary>
    internal async Task<KaevoPairingV3StatusResponse> GetLocalStatusAsync(CancellationToken cancellationToken = default)
    {
        if (!_enabled())
        {
            return new KaevoPairingV3StatusResponse("disabled", KaevoPairingV3Crypto.Protocol, false);
        }

        return await _store.ReadAsync(state =>
        {
            var connector = state.Connector;
            var paired = connector is not null
                && connector.Status == "active"
                && connector.ProtocolVersion == KaevoPairingV3Crypto.Protocol;
            return new KaevoPairingV3StatusResponse(
                paired ? "paired" : "not_paired",
                KaevoPairingV3Crypto.Protocol,
                false);
        }, cancellationToken).ConfigureAwait(false);
    }

    internal async Task<KaevoPairingV3Start> StartAsync(string serverId, string serverName, string localEndpoint, string setupUserId, CancellationToken cancellationToken = default)
    {
        RequireEnabled(); RequireBinding(serverId); RequireBinding(localEndpoint);
        var generated = await _store.MutateAsync(state =>
        {
            state.Identity ??= KaevoPairingV3Store.NewIdentity();
            KaevoPairingV3Store.ValidateIdentity(state.Identity);
            var ticketSecret = RandomNumberGenerator.GetBytes(32);
            try
            {
                var ticketId = KaevoPairingV3Crypto.Base64Url(RandomNumberGenerator.GetBytes(16));
                var verifier = KaevoPairingV3Crypto.PublicKeyFromSeed(KaevoPairingV3Crypto.DeriveChallengeSeed(ticketSecret, ticketId));
                var expiry = DateTimeOffset.UtcNow.AddSeconds(TicketLifetimeSeconds);
                var ticket = new KaevoPairingV3Ticket(ticketId, KaevoPairingV3Crypto.Base64Url(verifier), expiry, state.Identity.PluginInstanceId,
                    state.Identity.PublicKeyBase64Url, state.Identity.Fingerprint, serverId, serverName, localEndpoint, setupUserId);
                state.Tickets[ticketId] = ticket;
                return (ticket, secret: KaevoPairingV3Crypto.Base64Url(ticketSecret), identity: state.Identity);
            }
            finally { CryptographicOperations.ZeroMemory(ticketSecret); }
        }, cancellationToken).ConfigureAwait(false);
        var payload = KaevoPairingV3Crypto.Transcript("qr-ticket", ("ticketId", generated.ticket.TicketId), ("ticketSecret", generated.secret),
            ("expiresAt", generated.ticket.ExpiresAtUtc.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")), ("pluginInstanceId", generated.identity.PluginInstanceId),
            ("pluginPublicKey", generated.identity.PublicKeyBase64Url), ("pluginPublicKeyFingerprint", generated.identity.Fingerprint),
            ("jellyfinServerId", serverId), ("jellyfinServerName", serverName), ("localEndpoint", localEndpoint), ("jellyfinSetupUserId", setupUserId));
        var signature = KaevoPairingV3Crypto.Sign(KaevoPairingV3Crypto.Base64UrlDecode(generated.identity.PrivateKeyBase64Url), payload);
        var uri = "kaevo://pairing/v3?payload=" + Uri.EscapeDataString(KaevoPairingV3Crypto.Base64Url(payload)) + "&signature=" + Uri.EscapeDataString(signature);
        Observe("none", "none", "/kaevo/v3/pairing/start", "created", 201, "pairing_ticket_available");
        return new(KaevoPairingV3Crypto.Protocol, generated.ticket.TicketId, generated.ticket.ExpiresAtUtc, generated.identity.PluginInstanceId,
            generated.identity.PublicKeyBase64Url, generated.identity.Fingerprint, serverId, serverName, localEndpoint, uri, signature);
    }

    internal async Task<KaevoPairingV3ChallengeResponse> ChallengeAsync(string ticketId, string pairingAttemptId, string authorizationHash, string correlationId, CancellationToken cancellationToken = default)
    {
        RequireEnabled(); RequireCanonicalUuid(pairingAttemptId); RequireHash(authorizationHash); correlationId = NormalizeCorrelationId(correlationId);
        var response = await _store.MutateAsync(state =>
        {
            var ticket = GetTicket(state, ticketId);
            EnsureTicketAvailable(ticket);
            var nonce = KaevoPairingV3Crypto.Base64Url(RandomNumberGenerator.GetBytes(32));
            var challenge = new KaevoPairingV3Challenge(KaevoPairingV3Crypto.Base64Url(RandomNumberGenerator.GetBytes(16)), ticketId, pairingAttemptId,
                authorizationHash, KaevoPairingV3Crypto.HashText(nonce), DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddSeconds(ChallengeLifetimeSeconds));
            state.Challenges[challenge.ChallengeId] = challenge;
            return (ticket, challenge, nonce, identity: state.Identity ?? throw new InvalidOperationException("pairingV3IdentityMissing"));
        }, cancellationToken).ConfigureAwait(false);
        var transcript = KaevoPairingV3Crypto.ChallengeTranscript(response.ticket, response.challenge, response.nonce, authorizationHash);
        var signature = KaevoPairingV3Crypto.Sign(KaevoPairingV3Crypto.Base64UrlDecode(response.identity.PrivateKeyBase64Url), transcript);
        Observe(correlationId, pairingAttemptId, "/kaevo/v3/pairing/challenges", "issued", 201, "challenge_issued");
        return new(KaevoPairingV3Crypto.Protocol, response.challenge.ChallengeId, response.nonce, response.challenge.IssuedAtUtc, response.challenge.ExpiresAtUtc,
            response.ticket.PluginInstanceId, response.ticket.PluginFingerprint, response.ticket.JellyfinServerId, "/kaevo/v3/pairing/complete", signature, correlationId);
    }

    internal async Task<KaevoPairingV3CloudResult> CompleteAsync(Uri cloudBase, KaevoPairingV3Completion completion, CancellationToken cancellationToken = default)
    {
        RequireEnabled(); completion = completion with { CorrelationId = NormalizeCorrelationId(completion.CorrelationId) };
        // Prove possession of the QR-derived key before parsing or trusting the
        // Cloud authorization. This keeps the endpoint order aligned with the
        // protocol and avoids making authorization parsing an oracle.
        await _store.ReadAsync(state =>
        {
            var ticket = GetTicket(state, completion.TicketId);
            EnsureTicketAvailable(ticket);
            if (!state.Challenges.TryGetValue(completion.ChallengeId, out var challenge) || challenge.Used) throw new KaevoPairingV3Exception("challenge_replayed");
            if (challenge.ExpiresAtUtc <= DateTimeOffset.UtcNow) throw new KaevoPairingV3Exception("challenge_expired");
            if (completion.Protocol != KaevoPairingV3Crypto.Protocol || challenge.TicketId != ticket.TicketId || challenge.PairingAttemptId != completion.PairingAttemptId
                || !CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(challenge.NonceHash), Encoding.UTF8.GetBytes(KaevoPairingV3Crypto.HashText(completion.ChallengeNonce))))
                throw new KaevoPairingV3Exception("invalid_challenge_proof");
            var authorizationHash = KaevoPairingV3Crypto.HashText(completion.Authorization);
            if (!CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(challenge.PairingAuthorizationHash), Encoding.UTF8.GetBytes(authorizationHash))
                || !KaevoPairingV3Crypto.Verify(KaevoPairingV3Crypto.Base64UrlDecode(ticket.ChallengeVerificationPublicKey),
                    KaevoPairingV3Crypto.ChallengeTranscript(ticket, challenge, completion.ChallengeNonce, authorizationHash), completion.ChallengeResponseSignature))
                throw new KaevoPairingV3Exception("invalid_challenge_proof");
            return 0;
        }, cancellationToken).ConfigureAwait(false);
        var claims = VerifyAuthorization(completion.Authorization);
        var prepared = await _store.MutateAsync(state =>
        {
            var ticket = GetTicket(state, completion.TicketId);
            EnsureTicketAvailable(ticket);
            if (!state.Challenges.TryGetValue(completion.ChallengeId, out var challenge) || challenge.Used) throw new KaevoPairingV3Exception("challenge_replayed");
            if (challenge.ExpiresAtUtc <= DateTimeOffset.UtcNow) throw new KaevoPairingV3Exception("challenge_expired");
            if (completion.Protocol != KaevoPairingV3Crypto.Protocol || challenge.TicketId != ticket.TicketId || challenge.PairingAttemptId != completion.PairingAttemptId
                || !CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(challenge.NonceHash), Encoding.UTF8.GetBytes(KaevoPairingV3Crypto.HashText(completion.ChallengeNonce))))
                throw new KaevoPairingV3Exception("invalid_challenge_proof");
            var authorizationHash = KaevoPairingV3Crypto.HashText(completion.Authorization);
            if (!CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(challenge.PairingAuthorizationHash), Encoding.UTF8.GetBytes(authorizationHash)))
                throw new KaevoPairingV3Exception("binding_mismatch");
            var proof = KaevoPairingV3Crypto.ChallengeTranscript(ticket, challenge, completion.ChallengeNonce, authorizationHash);
            if (!KaevoPairingV3Crypto.Verify(KaevoPairingV3Crypto.Base64UrlDecode(ticket.ChallengeVerificationPublicKey), proof, completion.ChallengeResponseSignature))
                throw new KaevoPairingV3Exception("invalid_challenge_proof");
            VerifyBindings(ticket, completion, claims);
            var now = DateTimeOffset.UtcNow;
            var reserved = ticket with { State = "reserved", PairingAttemptId = claims.PairingAttemptId, ReservedAtUtc = now,
                ReservationExpiresAtUtc = now.AddSeconds(ReservationLifetimeSeconds), RedemptionState = "redemption_pending", AuthorizationJti = claims.Jti,
                AccountBinding = claims.AccountBinding, FamilyBinding = claims.FamilyBinding };
            state.Tickets[ticket.TicketId] = reserved;
            state.Challenges[challenge.ChallengeId] = challenge with { Used = true };
            return (ticket: reserved, identity: state.Identity ?? throw new InvalidOperationException("pairingV3IdentityMissing"), claims);
        }, cancellationToken).ConfigureAwait(false);
        Observe(completion.CorrelationId, completion.PairingAttemptId, "/kaevo/v3/pairing/complete", "available_to_reserved", 202, "pairing_reserved");
        var request = CreateRedemption(prepared.ticket, prepared.identity, prepared.claims, completion);
        var result = await _cloud.RedeemAsync(cloudBase, request, cancellationToken).ConfigureAwait(false);
        return await ApplyCloudResultAsync(prepared.ticket.TicketId, prepared.ticket.PairingAttemptId, completion.CorrelationId, result, cancellationToken).ConfigureAwait(false);
    }

    internal async Task<KaevoPairingV3CloudResult> RecoverAsync(Uri cloudBase, string ticketId, string correlationId, CancellationToken cancellationToken = default)
    {
        RequireEnabled(); correlationId = NormalizeCorrelationId(correlationId);
        var context = await _store.ReadAsync(state =>
        {
            var ticket = GetTicket(state, ticketId);
            if (ticket.State != "reserved" || string.IsNullOrWhiteSpace(ticket.PairingAttemptId) || string.IsNullOrWhiteSpace(ticket.AuthorizationJti)) throw new KaevoPairingV3Exception("pairing_status_pending", true);
            return (ticket, identity: state.Identity ?? throw new InvalidOperationException("pairingV3IdentityMissing"));
        }, cancellationToken).ConfigureAwait(false);
        var request = CreateStatus(context.ticket, context.identity, correlationId);
        var result = await _cloud.StatusAsync(cloudBase, request, cancellationToken).ConfigureAwait(false);
        return await ApplyCloudResultAsync(ticketId, context.ticket.PairingAttemptId, correlationId, result, cancellationToken).ConfigureAwait(false);
    }

    internal async Task<KaevoPairingV3SignedConnectorRequest> PrepareConnectorRequestAsync(string method, string canonicalRoute, object body, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(method) || string.IsNullOrWhiteSpace(canonicalRoute) || !canonicalRoute.StartsWith("/", StringComparison.Ordinal)
            || canonicalRoute.Contains('\r') || canonicalRoute.Contains('\n')) throw new KaevoPairingV3Exception("malformed_request");
        var context = await _store.ReadAsync(state =>
        {
            var identity = state.Identity ?? throw new KaevoPairingV3Exception("pairing_dependency_failure", true);
            var connector = state.Connector;
            if (connector is null || connector.Status != "active" || connector.ProtocolVersion != KaevoPairingV3Crypto.Protocol)
                throw new KaevoPairingV3Exception("pairing_dependency_failure", true);
            return (identity, connector);
        }, cancellationToken).ConfigureAwait(false);
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString(System.Globalization.CultureInfo.InvariantCulture);
        var nonce = KaevoPairingV3Crypto.Base64Url(RandomNumberGenerator.GetBytes(32));
        var digest = KaevoPairingV3Crypto.CanonicalJsonDigest(body);
        var keyId = context.identity.KeyVersion.ToString(System.Globalization.CultureInfo.InvariantCulture);
        var transcript = KaevoPairingV3Crypto.Transcript("connector-request", ("httpMethod", method.ToUpperInvariant()), ("canonicalRoute", canonicalRoute),
            ("bodyDigest", digest), ("timestamp", timestamp), ("nonce", nonce), ("connectorId", context.connector.ConnectorId),
            ("pluginInstanceId", context.identity.PluginInstanceId), ("pluginKeyId", keyId), ("pluginPublicKeyFingerprint", context.identity.Fingerprint));
        var signature = KaevoPairingV3Crypto.Sign(KaevoPairingV3Crypto.Base64UrlDecode(context.identity.PrivateKeyBase64Url), transcript);
        return new(context.connector.ConnectorId, keyId, timestamp, nonce, digest, signature);
    }

    private async Task<KaevoPairingV3CloudResult> ApplyCloudResultAsync(string ticketId, string pairingAttemptId, string correlationId, KaevoPairingV3CloudResult result, CancellationToken cancellationToken)
    {
        if (result.Code == "pairing_redeemed" && !string.IsNullOrWhiteSpace(result.ConnectorId))
        {
            await _store.MutateAsync(state =>
            {
                var ticket = GetTicket(state, ticketId);
                if (ticket.State != "reserved") throw new KaevoPairingV3Exception("ambiguous_enrollment", true);
                var connector = new KaevoPairingV3Connector(result.ConnectorId, ticket.PluginInstanceId, ticket.PluginPublicKey, ticket.PluginFingerprint,
                    state.Identity?.KeyVersion ?? 1, ticket.AccountBinding, ticket.FamilyBinding, ticket.JellyfinServerId, ticket.JellyfinSetupUserId,
                    DateTimeOffset.UtcNow, "active", ticket.PairingAttemptId, KaevoPairingV3Crypto.Protocol);
                state.Connector = connector;
                state.Tickets[ticketId] = ticket with { State = "consumed", RedemptionState = "redeemed", ConnectorId = result.ConnectorId, AuthorizationJti = "" };
                return 0;
            }, cancellationToken).ConfigureAwait(false);
            Observe(correlationId, pairingAttemptId, "/v3/home-connectors/pairing/redemptions", "reserved_to_consumed", 201, "pairing_redeemed");
            return result;
        }
        if (result.Code is "invalid_pairing_authorization" or "pairing_authorization_expired" or "binding_mismatch")
        {
            await ReleaseReservationAsync(ticketId, result.Code, cancellationToken).ConfigureAwait(false);
            Observe(correlationId, pairingAttemptId, "/v3/home-connectors/pairing/redemptions", "reserved_to_available", 422, result.Code);
            return result;
        }
        // Timeouts, 5xx, and unknown outcomes remain reserved; only status recovery can resolve them.
        Observe(correlationId, pairingAttemptId, "/v3/home-connectors/pairing/redemptions", "reserved", result.Retryable ? 202 : 409, result.Code);
        return result.Code is "cloud_unavailable" or "ambiguous_enrollment" ? result with { Code = "ambiguous_enrollment", Retryable = true } : result;
    }

    private async Task ReleaseReservationAsync(string ticketId, string reason, CancellationToken cancellationToken) =>
        await _store.MutateAsync(state =>
        {
            var ticket = GetTicket(state, ticketId);
            if (ticket.State == "reserved") state.Tickets[ticketId] = ticket with { State = "available", PairingAttemptId = "", ReservedAtUtc = null,
                ReservationExpiresAtUtc = null, RedemptionState = reason, AuthorizationJti = "" };
            return 0;
        }, cancellationToken).ConfigureAwait(false);

    private KaevoPairingV3RedemptionRequest CreateRedemption(KaevoPairingV3Ticket ticket, KaevoPairingV3Identity identity, PairingAuthorization claims, KaevoPairingV3Completion completion)
    {
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString(System.Globalization.CultureInfo.InvariantCulture);
        var nonce = KaevoPairingV3Crypto.Base64Url(RandomNumberGenerator.GetBytes(32));
        var body = new { protocol = KaevoPairingV3Crypto.Protocol, authorization = completion.Authorization, ticketId = ticket.TicketId,
            pairingAttemptId = ticket.PairingAttemptId, pluginInstanceId = identity.PluginInstanceId, pluginPublicKey = identity.PublicKeyBase64Url,
            pluginPublicKeyFingerprint = identity.Fingerprint, jellyfinServerId = ticket.JellyfinServerId, jellyfinUserId = completion.JellyfinUserId,
            pluginKeyId = identity.KeyVersion.ToString(System.Globalization.CultureInfo.InvariantCulture) };
        var signature = KaevoPairingV3Crypto.Sign(KaevoPairingV3Crypto.Base64UrlDecode(identity.PrivateKeyBase64Url),
            KaevoPairingV3Crypto.RedemptionTranscript("POST", "/v3/home-connectors/pairing/redemptions", KaevoPairingV3Crypto.CanonicalJsonDigest(body), timestamp, nonce,
                ticket.PairingAttemptId, claims.Jti, identity.PluginInstanceId, identity.Fingerprint, ticket.JellyfinServerId));
        return new(completion.Authorization, ticket.TicketId, ticket.PairingAttemptId, identity.PluginInstanceId, identity.PublicKeyBase64Url, identity.Fingerprint,
            ticket.JellyfinServerId, completion.JellyfinUserId, claims.Jti, identity.KeyVersion.ToString(System.Globalization.CultureInfo.InvariantCulture), timestamp, nonce, signature, completion.CorrelationId);
    }

    private KaevoPairingV3StatusRequest CreateStatus(KaevoPairingV3Ticket ticket, KaevoPairingV3Identity identity, string correlationId)
    {
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString(System.Globalization.CultureInfo.InvariantCulture);
        var nonce = KaevoPairingV3Crypto.Base64Url(RandomNumberGenerator.GetBytes(32));
        var body = new { protocol = KaevoPairingV3Crypto.Protocol, authorizationJti = ticket.AuthorizationJti, pairingAttemptId = ticket.PairingAttemptId,
            pluginInstanceId = identity.PluginInstanceId, pluginPublicKey = identity.PublicKeyBase64Url, pluginPublicKeyFingerprint = identity.Fingerprint,
            jellyfinServerId = ticket.JellyfinServerId, pluginKeyId = identity.KeyVersion.ToString(System.Globalization.CultureInfo.InvariantCulture) };
        var signature = KaevoPairingV3Crypto.Sign(KaevoPairingV3Crypto.Base64UrlDecode(identity.PrivateKeyBase64Url),
            KaevoPairingV3Crypto.Transcript("attempt-status", ("httpMethod", "POST"), ("canonicalRoute", "/v3/home-connectors/pairing/attempts/" + ticket.PairingAttemptId),
                ("bodyDigest", KaevoPairingV3Crypto.CanonicalJsonDigest(body)), ("timestamp", timestamp), ("nonce", nonce), ("pairingAttemptId", ticket.PairingAttemptId),
                ("authorizationJti", ticket.AuthorizationJti), ("pluginInstanceId", identity.PluginInstanceId), ("pluginPublicKeyFingerprint", identity.Fingerprint), ("jellyfinServerId", ticket.JellyfinServerId)));
        return new(ticket.PairingAttemptId, ticket.AuthorizationJti, identity.PluginInstanceId, identity.PublicKeyBase64Url, identity.Fingerprint, ticket.JellyfinServerId, timestamp, nonce, signature,
            identity.KeyVersion.ToString(System.Globalization.CultureInfo.InvariantCulture), correlationId);
    }

    private PairingAuthorization VerifyAuthorization(string token)
    {
        try
        {
            var parts = token.Split('.'); if (parts.Length != 3) throw new KaevoPairingV3Exception("invalid_pairing_authorization");
            using var header = JsonDocument.Parse(KaevoPairingV3Crypto.Base64UrlDecode(parts[0]));
            using var payload = JsonDocument.Parse(KaevoPairingV3Crypto.Base64UrlDecode(parts[1]));
            var kid = header.RootElement.GetProperty("kid").GetString() ?? "";
            if (header.RootElement.GetProperty("alg").GetString() != "EdDSA" || header.RootElement.GetProperty("typ").GetString() != "kaevo-pairing-authorization+jwt") throw new KaevoPairingV3Exception("invalid_pairing_authorization");
            var keys = JsonSerializer.Deserialize<Dictionary<string, string>>(_verificationKeys(), new JsonSerializerOptions(JsonSerializerDefaults.Web));
            if (keys is null || !keys.TryGetValue(kid, out var encodedKey) || !KaevoPairingV3Crypto.Verify(KaevoPairingV3Crypto.Base64UrlDecode(encodedKey), Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]), parts[2]))
                throw new KaevoPairingV3Exception("invalid_pairing_authorization");
            var root = payload.RootElement;
            var claims = new PairingAuthorization(
                root.GetProperty("iss").GetString() ?? "", root.GetProperty("sub").GetString() ?? "",
                root.GetProperty("jti").GetString() ?? "", root.GetProperty("pairingAttemptId").GetString() ?? "", root.GetProperty("ticketId").GetString() ?? "",
                root.GetProperty("pluginInstanceId").GetString() ?? "", root.GetProperty("pluginPublicKeyFingerprint").GetString() ?? "",
                root.GetProperty("jellyfinServerId").GetString() ?? "", root.GetProperty("jellyfinUserProvenance").GetString() ?? "",
                root.GetProperty("accountBinding").GetString() ?? "", root.GetProperty("familyBinding").GetString() ?? "", root.GetProperty("ownerSessionProvenance").GetString() ?? "",
                root.GetProperty("iosDeviceBinding").GetString() ?? "", root.GetProperty("entitlement").GetString() ?? "", root.GetProperty("iat").GetInt64(), root.GetProperty("nbf").GetInt64(), root.GetProperty("exp").GetInt64(),
                root.GetProperty("aud").GetString() ?? "", root.GetProperty("protocol").GetString() ?? "");
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (claims.ExpiresAtUnix <= now || claims.NotBeforeUnix > now || claims.IssuedAtUnix > now + 5) throw new KaevoPairingV3Exception("pairing_authorization_expired");
            if (claims.Audience != KaevoPairingV3Crypto.AuthorizationAudience || claims.Protocol != KaevoPairingV3Crypto.Protocol
                || claims.Issuer != _authorizationIssuer() || !Guid.TryParseExact(claims.Jti, "D", out _) || string.IsNullOrWhiteSpace(claims.Subject)
                || string.IsNullOrWhiteSpace(claims.OwnerSessionProvenance) || string.IsNullOrWhiteSpace(claims.IosDeviceBinding) || claims.Entitlement != "cloud_enabled") throw new KaevoPairingV3Exception("invalid_pairing_authorization");
            return claims;
        }
        catch (KaevoPairingV3Exception) { throw; }
        catch (Exception) { throw new KaevoPairingV3Exception("invalid_pairing_authorization"); }
    }

    private static void VerifyBindings(KaevoPairingV3Ticket ticket, KaevoPairingV3Completion completion, PairingAuthorization claims)
    {
        if (claims.PairingAttemptId != completion.PairingAttemptId || claims.TicketId != ticket.TicketId
            || claims.PluginInstanceId != ticket.PluginInstanceId || claims.PluginFingerprint != ticket.PluginFingerprint
            || claims.JellyfinServerId != ticket.JellyfinServerId || claims.JellyfinUserProvenance != KaevoPairingV3Crypto.HashText(completion.JellyfinUserId))
            throw new KaevoPairingV3Exception("binding_mismatch");
    }

    private static KaevoPairingV3Ticket GetTicket(KaevoPairingV3State state, string ticketId) =>
        state.Tickets.TryGetValue(ticketId, out var ticket) ? ticket : throw new KaevoPairingV3Exception("pairing_ticket_not_found");

    private static void EnsureTicketAvailable(KaevoPairingV3Ticket ticket)
    {
        if (ticket.ExpiresAtUtc <= DateTimeOffset.UtcNow) throw new KaevoPairingV3Exception("pairing_ticket_expired");
        if (ticket.State == "consumed") throw new KaevoPairingV3Exception("pairing_consumed");
        if (ticket.State == "reserved" && ticket.ReservationExpiresAtUtc > DateTimeOffset.UtcNow) throw new KaevoPairingV3Exception("pairing_reserved", true);
        if (ticket.State is not "available") throw new KaevoPairingV3Exception("ambiguous_enrollment", true);
    }

    private void RequireEnabled() { if (!_enabled()) throw new KaevoPairingV3Exception("pairing_v3_disabled"); }
    private static void RequireBinding(string value) { if (string.IsNullOrWhiteSpace(value) || value.Length > 512) throw new KaevoPairingV3Exception("malformed_request"); }
    private static void RequireHash(string value) { if (value.Length != 43 || value.Any(char.IsWhiteSpace)) throw new KaevoPairingV3Exception("malformed_request"); }
    private static void RequireCanonicalUuid(string value) { if (!Guid.TryParseExact(value, "D", out _) || value != value.ToLowerInvariant()) throw new KaevoPairingV3Exception("malformed_request"); }
    internal static string NormalizeCorrelationId(string value) => Guid.TryParseExact(value, "D", out _) && value == value.ToLowerInvariant() ? value : Guid.NewGuid().ToString("D");
    private void Observe(string correlationId, string pairingAttemptId, string route, string transition, int status, string outcome) =>
        _observe(correlationId, pairingAttemptId.Length >= 8 ? pairingAttemptId[..8] : "none", route, transition, status, outcome);

    private sealed record PairingAuthorization(string Issuer, string Subject, string Jti, string PairingAttemptId, string TicketId, string PluginInstanceId, string PluginFingerprint,
        string JellyfinServerId, string JellyfinUserProvenance, string AccountBinding, string FamilyBinding, string OwnerSessionProvenance,
        string IosDeviceBinding, string Entitlement, long IssuedAtUnix, long NotBeforeUnix, long ExpiresAtUnix, string Audience, string Protocol);
}
