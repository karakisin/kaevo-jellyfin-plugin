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
    [InlineData(nameof(KaevoController.GetProviderStatus))]
    [InlineData(nameof(KaevoController.ProvisionProvider))]
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
