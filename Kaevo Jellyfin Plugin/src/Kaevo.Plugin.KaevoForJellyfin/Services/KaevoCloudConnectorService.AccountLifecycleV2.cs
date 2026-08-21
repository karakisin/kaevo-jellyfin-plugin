using System.Text.Json;
using Kaevo.Plugin.KaevoForJellyfin.Configuration;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

public sealed partial class KaevoCloudConnectorService
{
    internal const string LifecycleV2SeerrDelete = "account_lifecycle_v2.seerr.delete_exact_identity";
    internal const string LifecycleV2SeerrVerify = "account_lifecycle_v2.seerr.verify_exact_identity_absence";
    internal const string LifecycleV2JellyfinDelete = "account_lifecycle_v2.jellyfin.delete_exact_identity";
    internal const string LifecycleV2JellyfinVerify = "account_lifecycle_v2.jellyfin.verify_exact_identity_absence";

    internal sealed record AccountLifecycleV2CommandContext(
        string OperationId,
        string LifecycleBindingId,
        string ProfileId,
        string ConnectorId,
        string JellyfinUserId,
        int? SeerrUserId);

    internal static bool IsAccountLifecycleV2Operation(string operation) =>
        operation is LifecycleV2SeerrDelete
            or LifecycleV2SeerrVerify
            or LifecycleV2JellyfinDelete
            or LifecycleV2JellyfinVerify;

    internal static AccountLifecycleV2CommandContext ValidateAccountLifecycleV2Command(
        PluginConfiguration configuration,
        CloudRequest request,
        string operation,
        IReadOnlyDictionary<string, JsonElement> parameters)
    {
        if (!IsAccountLifecycleV2Operation(operation))
        {
            throw new InvalidOperationException("accountLifecycleV2OperationInvalid");
        }

        KaevoTwoWayProfileDeletionPolicy.Require(configuration);
        var operationId = RequireLifecycleV2Identifier(
            RequireString(parameters, "operation_id", "accountLifecycleV2OperationIdInvalid"),
            "ald2_",
            "accountLifecycleV2OperationIdInvalid");
        var lifecycleBindingId = RequireLifecycleV2Identifier(
            RequireString(parameters, "lifecycle_binding_id", "accountLifecycleV2BindingIdInvalid"),
            null,
            "accountLifecycleV2BindingIdInvalid");
        var profileId = request.ProfileId;
        if (string.IsNullOrWhiteSpace(profileId) || profileId.Length > 256)
        {
            throw new InvalidOperationException("accountLifecycleV2ProfileIdInvalid");
        }

        var binding = request.ProfileProviderBinding;
        if (binding is null
            || !string.Equals(binding.Provider, "jellyfin", StringComparison.OrdinalIgnoreCase)
            || !string.Equals(binding.ConnectorId, configuration.ConnectorId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("accountLifecycleV2ProviderBindingInvalid");
        }

        var boundJellyfinUserId = RequireBoundJellyfinUserId(
            configuration,
            profileId,
            "accountLifecycleV2ProviderBindingMissing");
        var requestedJellyfinUserId = RequireString(
            parameters,
            "jellyfin_user_id",
            "accountLifecycleV2ProviderIdentityInvalid");
        if (!KaevoProfileJellyfinBindingStore.TryNormalizeJellyfinUserId(
                requestedJellyfinUserId,
                out var normalizedRequestedUserId)
            || !string.Equals(boundJellyfinUserId, normalizedRequestedUserId, StringComparison.Ordinal)
            || !KaevoProfileJellyfinBindingStore.TryNormalizeJellyfinUserId(
                binding.ProviderUserId,
                out var normalizedAuthoritativeUserId)
            || !string.Equals(boundJellyfinUserId, normalizedAuthoritativeUserId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("accountLifecycleV2ProviderIdentityMismatch");
        }

        int? seerrUserId = null;
        if (operation is LifecycleV2SeerrDelete or LifecycleV2SeerrVerify)
        {
            if (!parameters.TryGetValue("seerr_user_id", out var seerrIdValue)
                || !seerrIdValue.TryGetInt32(out var parsedSeerrUserId)
                || parsedSeerrUserId <= 0)
            {
                throw new InvalidOperationException("accountLifecycleV2ProviderIdentityInvalid");
            }
            seerrUserId = parsedSeerrUserId;
        }

        return new(
            operationId,
            lifecycleBindingId,
            profileId,
            configuration.ConnectorId,
            boundJellyfinUserId,
            seerrUserId);
    }

    private async Task<CommandResult> ExecuteAccountLifecycleV2CommandAsync(
        PluginConfiguration configuration,
        KaevoConnectorSecrets secrets,
        CloudRequest request,
        string operation,
        IReadOnlyDictionary<string, JsonElement> parameters,
        CancellationToken cancellationToken)
    {
        var context = ValidateAccountLifecycleV2Command(configuration, request, operation, parameters);

        if (operation == LifecycleV2SeerrDelete)
        {
            var result = await _seerrIdentityProvisioning.DispatchDeleteExactJellyfinUserAsync(
                secrets,
                context.JellyfinUserId,
                context.SeerrUserId!.Value,
                cancellationToken).ConfigureAwait(false);
            if (result.State is not ("delete_dispatched" or "already_absent"))
            {
                throw new InvalidOperationException(result.State);
            }
            return CompleteAccountLifecycleV2Command(request, operation, context, "seerr", result.State, false);
        }

        if (operation == LifecycleV2SeerrVerify)
        {
            var result = await _seerrIdentityProvisioning.VerifyExactJellyfinUserAbsentAsync(
                secrets,
                context.JellyfinUserId,
                context.SeerrUserId!.Value,
                cancellationToken).ConfigureAwait(false);
            if (result.State != "absence_confirmed")
            {
                throw new InvalidOperationException(result.State);
            }
            return CompleteAccountLifecycleV2Command(request, operation, context, "seerr", result.State, true);
        }

        var users = await SendLocalAsync(
            configuration,
            secrets,
            HttpMethod.Get,
            "/Users",
            null,
            null,
            cancellationToken).ConfigureAwait(false);
        var occurrences = ExactJellyfinUserOccurrences(users.Payload, context.JellyfinUserId);
        if (occurrences > 1)
        {
            throw new InvalidOperationException("accountLifecycleV2JellyfinIdentityAmbiguous");
        }

        if (operation == LifecycleV2JellyfinDelete)
        {
            if (occurrences == 1)
            {
                await SendLocalAsync(
                    configuration,
                    secrets,
                    HttpMethod.Delete,
                    $"/Users/{Uri.EscapeDataString(context.JellyfinUserId)}",
                    null,
                    null,
                    cancellationToken).ConfigureAwait(false);
            }
            return CompleteAccountLifecycleV2Command(
                request,
                operation,
                context,
                "jellyfin",
                occurrences == 0 ? "already_absent" : "delete_dispatched",
                false);
        }

        if (occurrences != 0)
        {
            throw new InvalidOperationException("accountLifecycleV2JellyfinIdentityStillPresent");
        }

        lock (ProfileBindingSync)
        {
            if (!KaevoProfileJellyfinBindingStore.TryUnbind(
                    configuration,
                    context.ProfileId,
                    context.JellyfinUserId))
            {
                throw new InvalidOperationException("accountLifecycleV2ProviderBindingConflict");
            }
            KaevoPlugin.Instance?.SaveConfiguration();
        }
        return CompleteAccountLifecycleV2Command(
            request,
            operation,
            context,
            "jellyfin",
            "absence_confirmed",
            true);
    }

    private static CommandResult CompleteAccountLifecycleV2Command(
        CloudRequest request,
        string operation,
        AccountLifecycleV2CommandContext context,
        string provider,
        string state,
        bool absenceConfirmed) =>
        CompleteCommand(request, operation, new
        {
            lifecycle_version = 2,
            operation_id = context.OperationId,
            lifecycle_binding_id = context.LifecycleBindingId,
            provider,
            state,
            connector_id = context.ConnectorId,
            profile_id = context.ProfileId,
            jellyfin_user_id = context.JellyfinUserId,
            seerr_user_id = context.SeerrUserId,
            absence_confirmed = absenceConfirmed
        });

    private static string RequireLifecycleV2Identifier(string value, string? prefix, string error)
    {
        if (value.Length is < 8 or > 128
            || (prefix is not null && !value.StartsWith(prefix, StringComparison.Ordinal))
            || value.Any(character =>
                !(char.IsAsciiLetterOrDigit(character) || character is '_' or '-')))
        {
            throw new InvalidOperationException(error);
        }
        return value;
    }
}
