using Kaevo.Plugin.KaevoForJellyfin.Services;
using Kaevo.Plugin.KaevoForJellyfin.Configuration;
using Xunit;
namespace Kaevo.Plugin.KaevoForJellyfin.Tests;
public sealed class SessionCredentialTests
{
    [Theory]
    [InlineData("same", "repaired")]
    [InlineData("connector", "original")]
    [InlineData("root", "original")]
    [InlineData("user", "original")]
    [InlineData("new-session", "original")]
    [InlineData("explicit", "original")]
    [InlineData("not-saved", "original")]
    public void ReplacementIsLimitedToSavedExactSession(string change, string expected)
    {
        var c = new PluginConfiguration { ConnectorId = "one", LocalJellyfinBaseUrl = "http://synthetic.invalid:8097", JellyfinUserId = "person" };
        var original = new KaevoConnectorSecrets("token", "grant", "original");
        var session = new KaevoJellyfinSessionCredential();
        Assert.Equal("original", session.Read(c, original, false));
        if (change != "not-saved") session.PublishSaved(KaevoJellyfinSessionCredential.Scope.From(c), original, "repaired");
        if (change == "connector") c.ConnectorId = "two";
        if (change == "root") c.LocalJellyfinBaseUrl = "http://other.invalid:8097";
        if (change == "user") c.JellyfinUserId = "different";
        Assert.Equal(expected, session.Read(c, change == "new-session" ? original with {} : original, change == "explicit"));
        Assert.Equal("original", original.JellyfinApiKey);
        Assert.Equal("token", original.ConnectorToken);
        Assert.Equal("grant", original.PlaybackGrantKey);
    }
    [Fact]
    public void ConfigurationChangedDuringSaveCannotRelabelVerifiedCredential()
    {
        var c = new PluginConfiguration { ConnectorId = "one", LocalJellyfinBaseUrl = "http://verified.invalid", JellyfinUserId = "person" };
        var original = new KaevoConnectorSecrets("token", "grant", "original");
        var session = new KaevoJellyfinSessionCredential();
        var scope = KaevoJellyfinSessionCredential.Scope.From(c);
        c.LocalJellyfinBaseUrl = "http://different.invalid";
        session.PublishSaved(scope, original, "repaired");
        Assert.Equal("original", session.Read(c, original, false));
    }
}
