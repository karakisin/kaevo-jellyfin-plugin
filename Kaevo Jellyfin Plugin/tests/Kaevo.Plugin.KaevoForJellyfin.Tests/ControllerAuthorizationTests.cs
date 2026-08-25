using Kaevo.Plugin.KaevoForJellyfin.Api;
using Microsoft.AspNetCore.Authorization;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class ControllerAuthorizationTests
{
    [Fact]
    public void KaevoControllerRequiresAuthenticatedJellyfinUserByDefault()
    {
        var attributes = typeof(KaevoController)
            .GetCustomAttributes(typeof(AuthorizeAttribute), inherit: true)
            .Cast<AuthorizeAttribute>()
            .ToArray();

        Assert.NotEmpty(attributes);
        Assert.Contains(attributes, attribute => string.IsNullOrWhiteSpace(attribute.Policy));
    }

    [Theory]
    [InlineData(nameof(KaevoController.ActivateCloud))]
    [InlineData(nameof(KaevoController.RefreshJellyfinCredential))]
    [InlineData(nameof(KaevoController.BindProfileJellyfinIdentity))]
    [InlineData(nameof(KaevoController.GetProviderStatus))]
    [InlineData(nameof(KaevoController.ProvisionProvider))]
    [InlineData(nameof(KaevoController.ProvisionSeerrJellyfinUser))]
    [InlineData(nameof(KaevoController.DeleteSeerrJellyfinUser))]
    [InlineData(nameof(KaevoController.PairLifecycle))]
    [InlineData(nameof(KaevoController.RotateLifecycle))]
    [InlineData(nameof(KaevoController.RecoverLifecycle))]
    [InlineData(nameof(KaevoController.RevokeLifecycle))]
    [InlineData(nameof(KaevoController.UnpairLifecycle))]
    [InlineData(nameof(KaevoController.ReconnectPairingV3))]
    [InlineData(nameof(KaevoController.GetPairingV3TicketStatus))]
    public void SensitiveConfigurationEndpointsRequireElevation(string methodName)
    {
        var method = typeof(KaevoController).GetMethod(methodName);
        Assert.NotNull(method);
        var policies = method!
            .GetCustomAttributes(typeof(AuthorizeAttribute), inherit: true)
            .Cast<AuthorizeAttribute>()
            .Select(attribute => attribute.Policy)
            .ToArray();

        Assert.Contains("RequiresElevation", policies);
    }
}
