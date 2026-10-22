using Kaevo.Plugin.KaevoForJellyfin.Configuration;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

public sealed partial class KaevoCloudConnectorService
{
    private async Task RecoverFirebaseAccountCleanupAsync(PluginConfiguration configuration,
        KaevoConnectorSecrets secrets, CancellationToken cancellationToken)
    {
        // Called only after the normal Firebase session has failed and drained.
        // This path can also run after process restart when the account freeze
        // intentionally prevents the normal startup heartbeat from succeeding.
        var body = await SendFirebaseControlAsync(configuration, "control-recovery", new
        {
            connector_id = configuration.ConnectorId,
            connector_control_protocol = ConnectorControlProtocolVersion,
            connector_control_transport = FirebaseAccountCleanupRecovery.Transport,
        }, cancellationToken).ConfigureAwait(false);
        var receipt = FirebaseAccountCleanupRecovery.Parse(body, configuration.ConnectorId, DateTimeOffset.UtcNow);
        await FirebaseAccountCleanupRecovery.RunBatchAsync(receipt,
            (id, token) => ClaimExactAsync(configuration, secrets, id, token),
            (request, token) => HandleClaimAsync(configuration, secrets, request, token),
            cancellationToken).ConfigureAwait(false);
    }
}
