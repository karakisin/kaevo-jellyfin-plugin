using System.Text.Json;
using Kaevo.Plugin.KaevoForJellyfin.Configuration;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class AccountLifecycleV2CommandTests
{
    private const string ProfileId = "profile_0123456789abcdef";
    private const string JellyfinUserId = "0123456789abcdef0123456789abcdef";
    private const string OperationId = "ald2_0123456789abcdef0123456789abcdef";

    [Fact]
    public void V2CommandsUseANewNamespaceAndDoNotRecognizeLegacyDeletion()
    {
        Assert.True(KaevoCloudConnectorService.IsAccountLifecycleV2Operation(
            KaevoCloudConnectorService.LifecycleV2SeerrDelete));
        Assert.True(KaevoCloudConnectorService.IsAccountLifecycleV2Operation(
            KaevoCloudConnectorService.LifecycleV2JellyfinVerify));
        Assert.False(KaevoCloudConnectorService.IsAccountLifecycleV2Operation(
            "jellyfin.delete_exact_bound_user"));
    }

    [Fact]
    public void V2ValidationRequiresTheLiveTwoWayDeletionPermission()
    {
        var configuration = Configuration(enabled: false);

        var error = Assert.Throws<InvalidOperationException>(() =>
            KaevoCloudConnectorService.ValidateAccountLifecycleV2Command(
                configuration,
                Request(KaevoCloudConnectorService.LifecycleV2JellyfinDelete),
                KaevoCloudConnectorService.LifecycleV2JellyfinDelete,
                Parameters()));

        Assert.Equal(KaevoTwoWayProfileDeletionPolicy.DisabledState, error.Message);
    }

    [Fact]
    public void V2ValidationCarriesOnlyExactImmutableAuthority()
    {
        var context = KaevoCloudConnectorService.ValidateAccountLifecycleV2Command(
            Configuration(enabled: true),
            Request(KaevoCloudConnectorService.LifecycleV2SeerrVerify),
            KaevoCloudConnectorService.LifecycleV2SeerrVerify,
            Parameters(includeSeerr: true));

        Assert.Equal(OperationId, context.OperationId);
        Assert.Equal("provider_binding_0123456789abcdef", context.LifecycleBindingId);
        Assert.Equal(ProfileId, context.ProfileId);
        Assert.Equal("connector-1", context.ConnectorId);
        Assert.Equal(JellyfinUserId, context.JellyfinUserId);
        Assert.Equal(42, context.SeerrUserId);
    }

    [Fact]
    public void V2ValidationRejectsACloudProviderIdentityMismatch()
    {
        var request = Request(
            KaevoCloudConnectorService.LifecycleV2JellyfinDelete,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

        var error = Assert.Throws<InvalidOperationException>(() =>
            KaevoCloudConnectorService.ValidateAccountLifecycleV2Command(
                Configuration(enabled: true),
                request,
                KaevoCloudConnectorService.LifecycleV2JellyfinDelete,
                Parameters()));

        Assert.Equal("accountLifecycleV2ProviderIdentityMismatch", error.Message);
    }

    [Fact]
    public void LifecycleClaimCannotRecreateAMissingLocalBinding()
    {
        var update = KaevoCloudConnectorService.AuthoritativeProfileProviderBindingUpdate(
            "connector-1", "{}", "", "", Request(KaevoCloudConnectorService.LifecycleV2JellyfinDelete));
        Assert.False(update.Changed);
        Assert.Equal("{}", update.BindingsJson);
        var config = Configuration(true);
        config.ProfileJellyfinBindingsJson = update.BindingsJson;
        Assert.Throws<InvalidOperationException>(() => KaevoCloudConnectorService.ValidateAccountLifecycleV2Command(
            config, Request(KaevoCloudConnectorService.LifecycleV2JellyfinDelete),
            KaevoCloudConnectorService.LifecycleV2JellyfinDelete, Parameters()));
    }

    [Fact]
    public void LostReplyAndRestartRecoverOnlyTheExactVerification()
    {
        WithStore((store, directory) =>
        {
            var config = Configuration(true);
            var request = Request(KaevoCloudConnectorService.LifecycleV2JellyfinVerify);
            var saved = "";
            KaevoCloudConnectorService.CompleteAccountLifecycleV2Unbind(config, request, Parameters(), store, 0,
                () => saved = config.ProfileJellyfinBindingsJson);
            Assert.Equal("{}", saved);
            var restarted = Configuration(true);
            restarted.ProfileJellyfinBindingsJson = saved;
            var recoveredStore = new KaevoAccountDeletionVerificationStore(directory);
            var context = KaevoCloudConnectorService.ValidateAccountLifecycleV2Command(restarted, request,
                KaevoCloudConnectorService.LifecycleV2JellyfinVerify, Parameters(), recoveredStore);
            Assert.True(recoveredStore.Contains(context));
            KaevoCloudConnectorService.CompleteAccountLifecycleV2Unbind(restarted, request, Parameters(), recoveredStore, 0, () => {});
            Assert.Equal("{}", restarted.ProfileJellyfinBindingsJson);
            foreach (var operation in new[] { KaevoCloudConnectorService.LifecycleV2JellyfinDelete,
                         KaevoCloudConnectorService.LifecycleV2SeerrDelete, KaevoCloudConnectorService.LifecycleV2SeerrVerify })
                Assert.Throws<InvalidOperationException>(() => KaevoCloudConnectorService.ValidateAccountLifecycleV2Command(
                    restarted, Request(operation), operation, Parameters(includeSeerr: true), recoveredStore));
            var bytes = File.ReadAllText(Directory.GetFiles(directory, "*.verified").Single());
            Assert.DoesNotContain(ProfileId, bytes);
            Assert.DoesNotContain(JellyfinUserId, bytes);
            Assert.DoesNotContain(OperationId, bytes);
        });
    }

    [Theory]
    [InlineData("operation_id", "ald2_different0123456789abcdef0123456789")]
    [InlineData("lifecycle_binding_id", "provider_binding_other0123456789")]
    [InlineData("profile_id", "profile_other0123456789")]
    public void RecoveryCannotChangeTheFrozenIdentity(string key, string value)
    {
        WithStore((store, _) =>
        {
            var config = Configuration(true);
            var request = Request(KaevoCloudConnectorService.LifecycleV2JellyfinVerify);
            KaevoCloudConnectorService.CompleteAccountLifecycleV2Unbind(config, request, Parameters(), store, 0, () => {});
            var changed = Parameters(); changed[key] = JsonSerializer.SerializeToElement(value);
            Assert.Throws<InvalidOperationException>(() => KaevoCloudConnectorService.ValidateAccountLifecycleV2Command(
                config, request, KaevoCloudConnectorService.LifecycleV2JellyfinVerify, changed, store));
        });
    }

    [Fact]
    public void RecoveryRequiresFreshAbsenceAndCurrentAdministratorPermission()
    {
        WithStore((store, _) =>
        {
            var config = Configuration(true);
            var request = Request(KaevoCloudConnectorService.LifecycleV2JellyfinVerify);
            KaevoCloudConnectorService.CompleteAccountLifecycleV2Unbind(config, request, Parameters(), store, 0, () => {});
            Assert.Throws<InvalidOperationException>(() => KaevoCloudConnectorService.CompleteAccountLifecycleV2Unbind(
                config, request, Parameters(), store, 1, () => throw new Exception("must not save")));
            config.TwoWayProfileDeletionEnabled = false;
            Assert.Throws<InvalidOperationException>(() => KaevoCloudConnectorService.CompleteAccountLifecycleV2Unbind(
                config, request, Parameters(), store, 0, () => throw new Exception("must not save")));
        });
    }

    [Theory]
    [InlineData("malformed")]
    [InlineData("{\"profile_0123456789abcdef\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}")]
    [InlineData("{\"profile_other0123456789\":\"0123456789abcdef0123456789abcdef\"}")]
    public void RecoveryCannotUnbindAChangedOrAmbiguousMap(string changed)
    {
        WithStore((store, _) =>
        {
            var config = Configuration(true);
            var request = Request(KaevoCloudConnectorService.LifecycleV2JellyfinVerify);
            KaevoCloudConnectorService.CompleteAccountLifecycleV2Unbind(config, request, Parameters(), store, 0, () => {});
            config.ProfileJellyfinBindingsJson = changed;
            Assert.Throws<InvalidOperationException>(() => KaevoCloudConnectorService.CompleteAccountLifecycleV2Unbind(
                config, request, Parameters(), store, 0, () => throw new Exception("must not save")));
            Assert.Equal(changed, config.ProfileJellyfinBindingsJson);
        });
    }

    [Fact]
    public void FailedConfigurationSavePreservesBindingAndAllowsReconciliation()
    {
        WithStore((store, _) =>
        {
            var config = Configuration(true); var before = config.ProfileJellyfinBindingsJson;
            var request = Request(KaevoCloudConnectorService.LifecycleV2JellyfinVerify);
            Assert.Throws<IOException>(() => KaevoCloudConnectorService.CompleteAccountLifecycleV2Unbind(
                config, request, Parameters(), store, 0, () => throw new IOException("simulated lost save")));
            Assert.Equal(before, config.ProfileJellyfinBindingsJson);
            KaevoCloudConnectorService.CompleteAccountLifecycleV2Unbind(config, request, Parameters(), store, 0, () => {});
            Assert.Equal("{}", config.ProfileJellyfinBindingsJson);
        });
    }

    [Fact]
    public void CorruptRecoveryRecordFailsClosedWithoutUnbinding()
    {
        WithStore((store, directory) =>
        {
            var config = Configuration(true); var before = config.ProfileJellyfinBindingsJson;
            var request = Request(KaevoCloudConnectorService.LifecycleV2JellyfinVerify);
            var context = KaevoCloudConnectorService.ValidateAccountLifecycleV2Command(config, request,
                KaevoCloudConnectorService.LifecycleV2JellyfinVerify, Parameters());
            store.RecordBeforeUnbind(context);
            File.WriteAllText(Directory.GetFiles(directory, "*.verified").Single(), "invalid");
            Assert.Throws<InvalidOperationException>(() => KaevoCloudConnectorService.CompleteAccountLifecycleV2Unbind(
                config, request, Parameters(), store, 0, () => {}));
            Assert.Equal(before, config.ProfileJellyfinBindingsJson);
        });
    }

    private static void WithStore(Action<KaevoAccountDeletionVerificationStore, string> work)
    {
        var directory = Path.Combine(Path.GetTempPath(), "kaevo-deletion-test-" + Guid.NewGuid().ToString("N"));
        try { work(new KaevoAccountDeletionVerificationStore(directory), directory); }
        finally { if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true); }
    }

    private static PluginConfiguration Configuration(bool enabled) => new()
    {
        ConnectorId = "connector-1",
        ProfileJellyfinBindingsJson = JsonSerializer.Serialize(new Dictionary<string, string>
        {
            [ProfileId] = JellyfinUserId
        }),
        TwoWayProfileDeletionEnabled = enabled
    };

    private static CloudRequest Request(string operation, string jellyfinUserId = JellyfinUserId) => new(
        "request-1",
        "COMMAND",
        "home_server",
        "/commands/" + operation,
        null,
        operation,
        null,
        ProfileId,
        new CloudProfileProviderBinding("jellyfin", "connector-1", jellyfinUserId));

    private static Dictionary<string, JsonElement> Parameters(bool includeSeerr = false)
    {
        var result = new Dictionary<string, JsonElement>
        {
            ["operation_id"] = JsonSerializer.SerializeToElement(OperationId),
            ["lifecycle_binding_id"] = JsonSerializer.SerializeToElement("provider_binding_0123456789abcdef"),
            ["jellyfin_user_id"] = JsonSerializer.SerializeToElement(JellyfinUserId)
        };
        if (includeSeerr)
        {
            result["seerr_user_id"] = JsonSerializer.SerializeToElement(42);
        }
        return result;
    }
}
