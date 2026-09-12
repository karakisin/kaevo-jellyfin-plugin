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
        IReadOnlyDictionary<string, JsonElement> parameters,
        KaevoAccountDeletionVerificationStore? verificationStore = null)
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
        if (string.IsNullOrWhiteSpace(profileId) || profileId.Length > 256
            || (parameters.ContainsKey("profile_id") && RequireString(parameters, "profile_id",
                "accountLifecycleV2ProfileIdInvalid") != profileId))
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

        var requestedJellyfinUserId = RequireString(
            parameters,
            "jellyfin_user_id",
            "accountLifecycleV2ProviderIdentityInvalid");
        if (!KaevoProfileJellyfinBindingStore.TryNormalizeJellyfinUserId(
                requestedJellyfinUserId,
                out var normalizedRequestedUserId)
            || !KaevoProfileJellyfinBindingStore.TryNormalizeJellyfinUserId(
                binding.ProviderUserId,
                out var normalizedAuthoritativeUserId)
            || !string.Equals(normalizedRequestedUserId, normalizedAuthoritativeUserId, StringComparison.Ordinal))
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

        var context = new AccountLifecycleV2CommandContext(
            operationId,
            lifecycleBindingId,
            profileId,
            configuration.ConnectorId,
            normalizedRequestedUserId,
            seerrUserId);
        if (KaevoProfileJellyfinBindingStore.TryResolve(configuration, profileId, out var boundUser))
        {
            if (boundUser != context.JellyfinUserId)
                throw new InvalidOperationException("accountLifecycleV2ProviderIdentityMismatch");
        }
        else if (operation != LifecycleV2JellyfinVerify
            || KaevoProfileJellyfinBindingStore.ProfileBindingState(configuration) != "ready"
            || verificationStore?.Contains(context) != true)
        {
            throw new InvalidOperationException("accountLifecycleV2ProviderBindingMissing");
        }
        return context;
    }

    private async Task<CommandResult> ExecuteAccountLifecycleV2CommandAsync(
        PluginConfiguration configuration,
        KaevoConnectorSecrets secrets,
        CloudRequest request,
        string operation,
        IReadOnlyDictionary<string, JsonElement> parameters,
        CancellationToken cancellationToken)
    {
        var verificationStore = new KaevoAccountDeletionVerificationStore(
            Path.Combine(_lifecycleStore.DirectoryPath, "account-deletion-verifications"));
        var context = ValidateAccountLifecycleV2Command(configuration, request, operation, parameters, verificationStore);

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

        CompleteAccountLifecycleV2Unbind(RuntimeConfiguration(configuration), request, parameters,
            verificationStore, occurrences, () =>
                (KaevoPlugin.Instance ?? throw new InvalidOperationException("pluginConfigurationUnavailable")).SaveConfiguration());
        return CompleteAccountLifecycleV2Command(
            request,
            operation,
            context,
            "jellyfin",
            "absence_confirmed",
            true);
    }

    internal static void CompleteAccountLifecycleV2Unbind(
        PluginConfiguration configuration, CloudRequest request,
        IReadOnlyDictionary<string, JsonElement> parameters,
        KaevoAccountDeletionVerificationStore verificationStore,
        int observedOccurrences, Action saveConfiguration)
    {
        if (observedOccurrences != 0)
            throw new InvalidOperationException("accountLifecycleV2JellyfinIdentityStillPresent");
        lock (ProfileBindingSync)
        {
            var context = ValidateAccountLifecycleV2Command(configuration, request,
                LifecycleV2JellyfinVerify, parameters, verificationStore);
            var previous = configuration.ProfileJellyfinBindingsJson;
            // Save the recovery record before the local authority can disappear.
            // A failed save leaves the original binding available for a new read.
            verificationStore.RecordBeforeUnbind(context);
            try
            {
                if (!KaevoProfileJellyfinBindingStore.TryUnbind(configuration,
                        context.ProfileId, context.JellyfinUserId))
                    throw new InvalidOperationException("accountLifecycleV2ProviderBindingConflict");
                saveConfiguration();
            }
            catch
            {
                configuration.ProfileJellyfinBindingsJson = previous;
                throw;
            }
        }
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
