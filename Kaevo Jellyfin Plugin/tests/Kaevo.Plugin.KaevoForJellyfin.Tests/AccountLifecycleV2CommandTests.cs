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
