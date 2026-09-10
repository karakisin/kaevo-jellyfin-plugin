using Google.Cloud.Firestore.V1;
using Kaevo.Plugin.KaevoForJellyfin.Configuration;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using System.Threading.Channels;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

public sealed partial class KaevoCloudConnectorService
{
    // Selected only after the normal startup path verifies a Firebase heartbeat.
    // Grant admission owns media demand; preparation alone never wakes a pool.
    private Task RunFirebaseRelayDemandAsync(PluginConfiguration configuration,
        KaevoConnectorSecrets secrets, IAsyncEnumerable<FirebaseRelayDemand> verifiedDemands,
        CancellationToken cancellationToken)
    {
        if (!_pairingV3Active || !configuration.RemotePlaybackEnabled)
            throw new InvalidOperationException("firebaseRelayDemandNotAdmitted");
        var began = System.Diagnostics.Stopwatch.StartNew();
        return FirebaseRelayDemandSupervisor.RunAsync(verifiedDemands,
            (_, activity, token) => RunRelayLoopAsync(configuration, secrets, token, activity.BeginVerifiedRequest),
            category => _logger.LogInformation("Kaevo Firebase media {Category} elapsed_ms={ElapsedMs}",
                category, began.ElapsedMilliseconds), cancellationToken);
    }

    // Normal Firebase transport owner. Startup has verified the handoff; the
    // control ticket independently requires activation on every renewal.
    private async Task RunFirebaseControlSupervisorAsync(PluginConfiguration configuration,
        KaevoConnectorSecrets secrets, string firebaseApiKey, CancellationToken cancellationToken)
    {
        if (!_pairingV3Active) throw new InvalidOperationException("lifecycle_upgrade_required");
        using var exchange = FirebaseControlTokenExchange.CreateClient();
        var client = FirebaseFirestoreControlListener.CreateDevelopmentClient();
        await RunFirebaseControlSupervisorCoreAsync(configuration, secrets,
            FirebaseControlAdmission.Parse,
            (admission, token) => FirebaseControlTokenExchange.ExchangeAsync(exchange, firebaseApiKey, admission, token),
            (admission, idToken, token) => FirebaseFirestoreControlListener.ReadAsync(client,
                FirebaseFirestoreControlListener.DevelopmentProject, admission.Channel, admission.Epoch,
                idToken, admission.ExpiresAt, token), cancellationToken).ConfigureAwait(false);
    }

    // Transport dependencies are explicit so the same owner can be exercised
    // with isolated emulator services. Normal startup supplies only the fixed
    // TLS clients, receipt parser and development project above; no settings or
    // request body can replace these dependencies.
    private async Task RunFirebaseControlSupervisorCoreAsync(PluginConfiguration configuration,
        KaevoConnectorSecrets secrets, Func<JsonElement, FirebaseControlAdmission> parseAdmission,
        Func<FirebaseControlAdmission, CancellationToken, Task<string>> exchangeToken,
        Func<FirebaseControlAdmission, string, CancellationToken, IAsyncEnumerable<string>> listen,
        CancellationToken cancellationToken)
    {
        if (!_pairingV3Active) throw new InvalidOperationException("lifecycle_upgrade_required");
        using var owner = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        string currentToken = string.Empty;
        FirebaseControlAdmission? currentAdmission = null;
        var began = System.Diagnostics.Stopwatch.StartNew();
        var hints = FirebaseControlSupervisor.ReadAsync(async token =>
        {
            currentToken = string.Empty;
            currentAdmission = null;
            var body = await SendFirebaseControlAsync(configuration, "control-ticket", new
            {
                connector_id = configuration.ConnectorId,
                connector_control_protocol = ConnectorControlProtocolVersion,
                connector_control_transport = "firestore-signals-v1",
            }, token).ConfigureAwait(false);
            var admission = parseAdmission(body);
            KaevoFirebaseRuntime.RequireAdmission(admission);
            currentToken = await exchangeToken(admission, token).ConfigureAwait(false);
            currentAdmission = admission;
            return admission;
        }, (admission, token) => listen(admission, currentToken, token), async (admission, token) =>
        {
            var body = await SendFirebaseControlAsync(configuration, "control-recovery", new
            {
                connector_id = configuration.ConnectorId,
                connector_control_protocol = ConnectorControlProtocolVersion,
                connector_control_transport = "firestore-signals-v1",
                connection_id = admission.Channel,
                epoch = admission.Epoch,
            }, token).ConfigureAwait(false);
            return FirebaseControlRecovery.Parse(body, admission);
        }, category => _logger.LogInformation("Kaevo Firebase control {Category} elapsed_ms={ElapsedMs}",
            category, began.ElapsedMilliseconds), owner.Token,
            recoverDemands: configuration.RemotePlaybackEnabled ? async (admission, token) =>
            {
                var response = await SendFirebaseControlAsync(configuration, "relay-demand-recovery", new
                {
                    connector_id = configuration.ConnectorId, connection_id = admission.Channel, epoch = admission.Epoch,
                    connector_control_protocol = ConnectorControlProtocolVersion,
                    connector_control_transport = "firestore-signals-v1",
                }, token).ConfigureAwait(false);
                return FirebaseRelayDemandRecovery.Parse(response, admission);
            } : null);
        // Read notifications independently of the four retained provider slots:
        // a long-running provider operation must not starve a playback wake.
        // Both queues apply bounded backpressure; no detached work/tasks.
        var commands = Channel.CreateBounded<string>(new BoundedChannelOptions(64)
            { SingleReader = true, SingleWriter = true, FullMode = BoundedChannelFullMode.Wait });
        var demands = Channel.CreateBounded<FirebaseRelayDemand>(new BoundedChannelOptions(128)
            { SingleReader = true, SingleWriter = true, FullMode = BoundedChannelFullMode.Wait });
        async Task PumpAsync()
        {
            Exception? failure = null;
            try
            {
                var filtered = FirebaseRelayDemandAdmission.FilterAsync(hints, async (id, token) =>
                {
                    if (!configuration.RemotePlaybackEnabled || currentAdmission is not { } admission)
                        throw new InvalidOperationException("firebaseRelayDemandNotAdmitted");
                    admission.Check();
                    var response = await SendFirebaseControlAsync(configuration,
                        $"relay-demands/{id}/admit", new
                        {
                            connector_id = configuration.ConnectorId, demand_id = id,
                            connection_id = admission.Channel, epoch = admission.Epoch,
                            connector_control_protocol = ConnectorControlProtocolVersion,
                            connector_control_transport = "firestore-signals-v1",
                        }, token).ConfigureAwait(false);
                    return FirebaseRelayDemandAdmission.Parse(response, configuration.ConnectorId, id, admission);
                }, (demand, token) => demands.Writer.WriteAsync(demand, token),
                    category => _logger.LogInformation("Kaevo Firebase media {Category} elapsed_ms={ElapsedMs}",
                        category, began.ElapsedMilliseconds), owner.Token);
                await foreach (var id in filtered.WithCancellation(owner.Token).ConfigureAwait(false))
                    await commands.Writer.WriteAsync(id, owner.Token).ConfigureAwait(false);
            }
            catch (Exception error) { failure = error; throw; }
            finally { commands.Writer.TryComplete(failure); demands.Writer.TryComplete(failure); }
        }
        async Task HeartbeatsAsync()
        {
            while (!owner.IsCancellationRequested)
            {
                await Task.Delay(TimeSpan.FromSeconds(60), owner.Token).ConfigureAwait(false);
                await HeartbeatAsync(configuration, secrets, owner.Token).ConfigureAwait(false);
            }
        }
        var tasks = new List<Task> { PumpAsync(), HeartbeatsAsync(), FirebaseControlDispatch.RunAsync(commands.Reader.ReadAllAsync(owner.Token),
            (id, token) => ClaimExactAsync(configuration, secrets, id, token),
            (request, token) => HandleClaimAsync(configuration, secrets, request, token),
            request => request.RequestId, ControlRequestConcurrency, cancellationToken) };
        if (configuration.RemotePlaybackEnabled)
            tasks.Add(RunFirebaseRelayDemandAsync(configuration, secrets,
                demands.Reader.ReadAllAsync(owner.Token), owner.Token));
        try
        {
            // A failed owner stops new admissions. Already claimed provider work
            // retains the host token and drains before this method returns.
            await Task.WhenAny(tasks).ConfigureAwait(false);
        }
        finally
        {
            owner.Cancel();
            try { await Task.WhenAll(tasks).ConfigureAwait(false); }
            finally { currentToken = string.Empty; currentAdmission = null; }
        }
    }

    private async Task<JsonElement> SendFirebaseControlAsync(PluginConfiguration configuration,
        string operation, object body, CancellationToken cancellationToken)
    {
        if (!_pairingV3Active || (operation is not ("control-ticket" or "control-recovery" or "relay-demand-recovery")
            && !FirebaseRelayDemandAdmission.IsAdmissionOperation(operation)))
            throw new InvalidOperationException("firebaseControlRouteInvalid");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(15));
        try
        {
            var path = $"/v3/home-connectors/{Uri.EscapeDataString(configuration.ConnectorId)}/{operation}";
            // Each invocation uses the existing signer and a new nonce. Never
            // replay a signed request after an uncertain admission response.
            using var response = await _pairingV3.SendConnectorRequestAsync(
                new Uri(configuration.CloudBaseUrl, UriKind.Absolute), HttpMethod.Post, path, body, deadline.Token).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode || response.Content.Headers.ContentLength is > 16384)
                throw new InvalidOperationException();
            await using var stream = await response.Content.ReadAsStreamAsync(deadline.Token).ConfigureAwait(false);
            var bytes = new byte[16385]; var size = 0;
            while (size < bytes.Length)
            {
                var read = await stream.ReadAsync(bytes.AsMemory(size), deadline.Token).ConfigureAwait(false);
                if (read == 0) break;
                size += read;
            }
            if (size == bytes.Length) throw new InvalidOperationException();
            using var document = JsonDocument.Parse(bytes.AsMemory(0, size), new JsonDocumentOptions { MaxDepth = 8 });
            return document.RootElement.Clone();
        }
        catch (Exception)
        {
            cancellationToken.ThrowIfCancellationRequested();
            throw new InvalidOperationException("firebaseControlRequestFailed");
        }
    }

    private async Task RunFirebaseAdmittedSessionAsync(PluginConfiguration configuration,
        KaevoConnectorSecrets secrets, System.Text.Json.JsonElement signedTicketResponse,
        string firebaseApiKey, CancellationToken cancellationToken)
    {
        if (!_pairingV3Active) throw new InvalidOperationException("lifecycle_upgrade_required");
        var admission = FirebaseControlAdmission.Parse(signedTicketResponse);
        using var exchange = FirebaseControlTokenExchange.CreateClient();
        var token = await FirebaseControlTokenExchange.ExchangeAsync(exchange, firebaseApiKey, admission, cancellationToken).ConfigureAwait(false);
        await RunFirebaseControlSessionAsync(configuration, secrets,
            FirebaseFirestoreControlListener.CreateDevelopmentClient(), admission.Channel,
            admission.Epoch, token, admission.ExpiresAt, cancellationToken).ConfigureAwait(false);
    }

    // Explicit session seam, not selected by RunControlLoopAsync or settings.
    // A future admitted runtime must supply an exchanged, memory-only ID token
    // and exact server-owned channel receipt. Never infer activation from URL,
    // imported configuration, a Firebase user sign-in, or a successful test.
    private Task RunFirebaseControlSessionAsync(
        PluginConfiguration configuration,
        KaevoConnectorSecrets secrets,
        FirestoreClient client,
        string channel,
        string epoch,
        string idToken,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken)
    {
        if (!_pairingV3Active)
            throw new InvalidOperationException("lifecycle_upgrade_required");
        return FirebaseControlDispatch.RunAsync(
            FirebaseFirestoreControlListener.ReadAsync(client,
                FirebaseFirestoreControlListener.DevelopmentProject,
                channel, epoch, idToken, expiresAt, cancellationToken),
            (id, token) => ClaimExactAsync(configuration, secrets, id, token),
            (request, token) => HandleClaimAsync(configuration, secrets, request, token),
            request => request.RequestId,
            ControlRequestConcurrency, cancellationToken);
    }
}
