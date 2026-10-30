using System.Net.Http;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;
namespace Kaevo.Plugin.KaevoForJellyfin.Tests;
public sealed class JellyfinAuthorizationHeaderTests
{
    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("key\r\nInjected: value")]
    [InlineData("key\", UserId=\"other")]
    [InlineData("key\\suffix")]
    public void MalformedKeysFailBeforeSending(string key)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "http://fixture.invalid/Users");
        var error = Assert.Throws<InvalidOperationException>(() =>
            KaevoCloudConnectorService.ApplyJellyfinAuthentication(request, key));
        Assert.Equal("jellyfinApiKeyInvalid", error.Message);
        Assert.Null(request.Headers.Authorization);
    }
    [Fact]
    public void UsesExistingKeyWithoutChangingProfileScopeOrUrl()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get,
            "http://fixture.invalid/Users/exact-user/Items/exact-item");
        KaevoCloudConnectorService.ApplyJellyfinAuthentication(request, "synthetic-api-key");
        Assert.Equal("MediaBrowser", request.Headers.Authorization?.Scheme);
        Assert.Contains("Token=\"synthetic-api-key\"", request.Headers.Authorization?.Parameter);
        Assert.Equal("/Users/exact-user/Items/exact-item", request.RequestUri!.AbsolutePath);
        Assert.Empty(request.RequestUri.Query);
        Assert.False(request.Headers.Contains("X-Emby-Token"));
    }
}
