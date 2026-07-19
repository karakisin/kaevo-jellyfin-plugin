using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

public sealed record KaevoLifecycleResult(string State, string ConnectorId, string ServerId, int CredentialVersion);

public sealed class KaevoConnectorLifecycleClient
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly KaevoConnectorLifecycleStore _store;
    private readonly HttpClient _http;

    public KaevoConnectorLifecycleClient(KaevoConnectorLifecycleStore store)
        : this(store, new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(15) })
    {
    }

    internal KaevoConnectorLifecycleClient(KaevoConnectorLifecycleStore store, HttpClient http)
    {
        _store = store;
        _http = http;
    }

    public async Task<KaevoLifecycleResult> PairAsync(Uri cloudBase, string ownerToken, string profileId, CancellationToken cancellationToken)
    {
        var existing = await _store.LoadOrInitializeAsync(cancellationToken).ConfigureAwait(false);
        if (!string.IsNullOrEmpty(existing.PendingKeyFile))
        {
            var reconciled = await ReconcilePendingAsync(cloudBase, profileId, cancellationToken).ConfigureAwait(false);
            if (reconciled.State == "active") return Result(reconciled);
        }
        var (pending, proposed) = await _store.BeginTransitionAsync("pair", cancellationToken).ConfigureAwait(false);
        using (proposed)
        using (var recovery = _store.LoadRecovery(pending))
        {
            var nonce = Nonce();
            try
            {
                var startUri = Build(cloudBase, "/v1/home-connectors/pairing/start");
                var start = await PostAsync<PairingStart>(startUri, new
                {
                    server_id = pending.ServerId,
                    local_nonce = nonce,
                    public_jwk = proposed.PublicJwk,
                    recovery_public_jwk = recovery.PublicJwk,
                    connector_name = "Kaevo Jellyfin Plugin"
                }, cancellationToken, ownerToken, ("DPoP", proposed.CreateProof(HttpMethod.Post, startUri)),
                    ("DPoP-Recovery", recovery.CreateProof(HttpMethod.Post, startUri))).ConfigureAwait(false);
                pending = await _store.BindPendingConnectorAsync(start.ConnectorId, cancellationToken).ConfigureAwait(false);
                var exchangeUri = Build(cloudBase, "/v2/home-connectors/pairing/exchange");
                var exchange = await PostAsync<LifecycleResponse>(exchangeUri, new
                {
                    connector_id = start.ConnectorId,
                    intent_id = start.IntentId,
                    pairing_code = start.PairingCode,
                    local_nonce = nonce,
                    public_jwk = proposed.PublicJwk
                }, cancellationToken, null, ("DPoP", proposed.CreateProof(HttpMethod.Post, exchangeUri))).ConfigureAwait(false);
                var committed = await _store.CommitTransitionAsync(exchange.ConnectorId, exchange.CredentialVersion, cancellationToken).ConfigureAwait(false);
                return Result(committed);
            }
            catch
            {
                await _store.AbortTransitionAsync(cancellationToken).ConfigureAwait(false);
                throw;
            }
        }
    }

    public async Task<KaevoConnectorLifecycleState> ReconcilePendingAsync(Uri cloudBase, string profileId, CancellationToken cancellationToken)
    {
        var state = await _store.LoadOrInitializeAsync(cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrEmpty(state.PendingKeyFile)) return state;
        if (string.IsNullOrWhiteSpace(state.ConnectorId) || string.IsNullOrWhiteSpace(profileId))
        {
            if (state.CredentialVersion == 0) return await _store.AbortTransitionAsync(cancellationToken).ConfigureAwait(false);
            throw new InvalidOperationException("connectorLifecycleReconciliationRequired");
        }

        var targetVersion = state.CredentialVersion + 1;
        using (var pending = _store.LoadPending(state))
        {
            var pendingAccepted = await ProbeRegistrationAsync(cloudBase, profileId, state.ConnectorId, targetVersion, pending, cancellationToken).ConfigureAwait(false);
            if (pendingAccepted)
            {
                return await _store.CommitTransitionAsync(state.ConnectorId, targetVersion, cancellationToken).ConfigureAwait(false);
            }
        }

        if (state.CredentialVersion > 0)
        {
            using var current = _store.LoadCurrent(state);
            if (await ProbeRegistrationAsync(cloudBase, profileId, state.ConnectorId, state.CredentialVersion, current, cancellationToken).ConfigureAwait(false))
            {
                return await _store.AbortTransitionAsync(cancellationToken).ConfigureAwait(false);
            }
        }
        throw new InvalidOperationException("connectorLifecycleReconciliationRequired");
    }

    private async Task<bool> ProbeRegistrationAsync(Uri cloudBase, string profileId, string connectorId, int version, KaevoConnectorIdentity identity, CancellationToken cancellationToken)
    {
        var uri = Build(cloudBase, $"/v1/home-connectors/{Uri.EscapeDataString(connectorId)}/heartbeat");
        using var request = new HttpRequestMessage(HttpMethod.Post, uri)
        {
            Content = new StringContent(JsonSerializer.Serialize(new
            {
                connector_id = connectorId, profile_id = profileId, provider_status = new { }
            }, JsonOptions), Encoding.UTF8, "application/json")
        };
        request.Headers.TryAddWithoutValidation("DPoP", identity.CreateProof(HttpMethod.Post, uri));
        request.Headers.TryAddWithoutValidation("X-Kaevo-Credential-Version", version.ToString());
        using var response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        return response.IsSuccessStatusCode;
    }

    public Task<KaevoLifecycleResult> RotateAsync(Uri cloudBase, string ownerToken, string profileId, CancellationToken cancellationToken) =>
        UpdateKeyAsync(cloudBase, ownerToken, profileId, "rotation", cancellationToken);

    public Task<KaevoLifecycleResult> RecoverAsync(Uri cloudBase, string ownerToken, string profileId, CancellationToken cancellationToken) =>
        UpdateKeyAsync(cloudBase, ownerToken, profileId, "recovery", cancellationToken);

    private async Task<KaevoLifecycleResult> UpdateKeyAsync(Uri cloudBase, string ownerToken, string profileId, string operation, CancellationToken cancellationToken)
    {
        var before = await _store.LoadOrInitializeAsync(cancellationToken).ConfigureAwait(false);
        if (!string.IsNullOrEmpty(before.PendingKeyFile))
        {
            return Result(await ReconcilePendingAsync(cloudBase, profileId, cancellationToken).ConfigureAwait(false));
        }
        if (before.CredentialVersion < 1 || string.IsNullOrEmpty(before.ConnectorId)) throw new InvalidOperationException("connectorLifecycleNotPaired");
        var storeOperation = operation == "rotation" ? "rotate" : "recover";
        var (pending, proposed) = await _store.BeginTransitionAsync(storeOperation, cancellationToken).ConfigureAwait(false);
        using (proposed)
        using (var current = _store.LoadCurrent(before))
        using (var recovery = _store.LoadRecovery(before))
        {
            var nonce = Nonce();
            try
            {
                var startUri = Build(cloudBase, $"/v2/home-connectors/{Uri.EscapeDataString(before.ConnectorId)}/{operation}-intents");
                var proofs = new List<(string, string)>
                {
                    ("DPoP-New", proposed.CreateProof(HttpMethod.Post, startUri)),
                    ("X-Kaevo-Credential-Version", before.CredentialVersion.ToString())
                };
                proofs.Add(operation == "rotation"
                    ? ("DPoP", current.CreateProof(HttpMethod.Post, startUri))
                    : ("DPoP-Recovery", recovery.CreateProof(HttpMethod.Post, startUri)));
                var start = await PostAsync<IntentResponse>(startUri, new
                {
                    server_id = before.ServerId, local_nonce = nonce, public_jwk = proposed.PublicJwk
                }, cancellationToken, ownerToken, proofs.ToArray()).ConfigureAwait(false);
                if (start.TargetVersion != before.CredentialVersion + 1) throw new InvalidOperationException("connectorLifecycleVersionInvalid");
                var activateUri = Build(cloudBase, $"/v2/home-connectors/lifecycle/intents/{Uri.EscapeDataString(start.IntentId)}/activate");
                proofs = new()
                {
                    ("DPoP-New", proposed.CreateProof(HttpMethod.Post, activateUri)),
                    ("X-Kaevo-Credential-Version", before.CredentialVersion.ToString())
                };
                proofs.Add(operation == "rotation"
                    ? ("DPoP", current.CreateProof(HttpMethod.Post, activateUri))
                    : ("DPoP-Recovery", recovery.CreateProof(HttpMethod.Post, activateUri)));
                var activated = await PostAsync<LifecycleResponse>(activateUri, new
                {
                    local_nonce = nonce, public_jwk = proposed.PublicJwk
                }, cancellationToken, null, proofs.ToArray()).ConfigureAwait(false);
                var committed = await _store.CommitTransitionAsync(activated.ConnectorId, activated.CredentialVersion, cancellationToken).ConfigureAwait(false);
                return Result(committed);
            }
            catch
            {
                await _store.AbortTransitionAsync(cancellationToken).ConfigureAwait(false);
                throw;
            }
        }
    }

    public async Task<KaevoLifecycleResult> RevokeAsync(Uri cloudBase, string ownerToken, CancellationToken cancellationToken)
    {
        var state = await _store.LoadOrInitializeAsync(cancellationToken).ConfigureAwait(false);
        var uri = Build(cloudBase, $"/v1/home-connectors/{Uri.EscapeDataString(state.ConnectorId)}/revoke");
        await PostAsync<JsonElement>(uri, new { }, cancellationToken, ownerToken).ConfigureAwait(false);
        return Result(await _store.SetTerminalStateAsync("revoked", cancellationToken).ConfigureAwait(false));
    }

    public async Task<KaevoLifecycleResult> UnpairAsync(Uri cloudBase, string ownerToken, CancellationToken cancellationToken)
    {
        var state = await _store.LoadOrInitializeAsync(cancellationToken).ConfigureAwait(false);
        var nonce = Nonce();
        var startUri = Build(cloudBase, $"/v2/home-connectors/{Uri.EscapeDataString(state.ConnectorId)}/unpair-intents");
        var intent = await PostAsync<IntentResponse>(startUri, new { server_id = state.ServerId, local_nonce = nonce }, cancellationToken, ownerToken).ConfigureAwait(false);
        var activateUri = Build(cloudBase, $"/v2/home-connectors/lifecycle/intents/{Uri.EscapeDataString(intent.IntentId)}/unpair");
        await PostAsync<JsonElement>(activateUri, new { local_nonce = nonce }, cancellationToken, ownerToken).ConfigureAwait(false);
        return Result(await _store.SetTerminalStateAsync("unpaired", cancellationToken).ConfigureAwait(false));
    }

    public async Task<HttpResponseMessage> SendConnectorAsync(Uri cloudBase, HttpMethod method, string path, object body, CancellationToken cancellationToken)
    {
        var state = await _store.LoadOrInitializeAsync(cancellationToken).ConfigureAwait(false);
        using var identity = _store.LoadCurrent(state);
        var uri = Build(cloudBase, path);
        var request = new HttpRequestMessage(method, uri)
        {
            Content = new StringContent(JsonSerializer.Serialize(body, JsonOptions), Encoding.UTF8, "application/json")
        };
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.TryAddWithoutValidation("DPoP", identity.CreateProof(method, uri));
        request.Headers.TryAddWithoutValidation("X-Kaevo-Credential-Version", state.CredentialVersion.ToString());
        return await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
    }

    private async Task<T> PostAsync<T>(Uri uri, object body, CancellationToken cancellationToken, string? ownerToken, params (string Name, string Value)[] headers)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, uri)
        {
            Content = new StringContent(JsonSerializer.Serialize(body, JsonOptions), Encoding.UTF8, "application/json")
        };
        if (!string.IsNullOrWhiteSpace(ownerToken)) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", ownerToken);
        foreach (var (name, value) in headers) request.Headers.TryAddWithoutValidation(name, value);
        using var response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode) throw new InvalidOperationException($"cloudHttp{(int)response.StatusCode}");
        return (await JsonSerializer.DeserializeAsync<T>(await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false), JsonOptions, cancellationToken).ConfigureAwait(false))!;
    }

    private static Uri Build(Uri baseUri, string path) => new(new Uri(baseUri.ToString().TrimEnd('/') + "/"), path.TrimStart('/'));
    private static string Nonce() => KaevoConnectorIdentity.Base64Url(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
    private static KaevoLifecycleResult Result(KaevoConnectorLifecycleState state) => new(state.State, state.ConnectorId, state.ServerId, state.CredentialVersion);

    private sealed record PairingStart(
        [property: JsonPropertyName("connector_id")] string ConnectorId,
        [property: JsonPropertyName("intent_id")] string IntentId,
        [property: JsonPropertyName("pairing_code")] string PairingCode);
    private sealed record IntentResponse(
        [property: JsonPropertyName("intent_id")] string IntentId,
        [property: JsonPropertyName("target_version")] int TargetVersion);
    private sealed record LifecycleResponse(
        [property: JsonPropertyName("connector_id")] string ConnectorId,
        [property: JsonPropertyName("server_id")] string ServerId,
        [property: JsonPropertyName("credential_version")] int CredentialVersion);
}
