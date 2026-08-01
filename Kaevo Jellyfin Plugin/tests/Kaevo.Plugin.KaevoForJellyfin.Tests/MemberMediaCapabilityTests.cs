using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Kaevo.Plugin.KaevoForJellyfin.Configuration;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class MemberMediaCapabilityTests
{
    private const string Connector = "connector-v3-test";
    private const string Profile = "profile-member-test";
    private const string User = "01234567-89ab-cdef-0123-456789abcdef";
    private const string Issuer = "kaevo-cloud-test";
    private const long Now = 2_000_000_000;
    private static readonly byte[] SigningSeed = Enumerable.Repeat((byte)13, 32).ToArray();

    [Fact]
    public void ValidCapabilityResolvesOnlyTheExactBoundJellyfinUser()
    {
        var fixture = Fixture();

        var resolved = KaevoMemberMediaCapabilityVerifier.Verify(
            Capability(fixture, new[] { "metadata.read", "library.read", "progress.read" }),
            fixture.Context,
            fixture.Keys,
            Issuer,
            Now);

        Assert.Equal(User.Replace("-", string.Empty, StringComparison.Ordinal), resolved.JellyfinUserId);
        Assert.Contains("library.read", resolved.Scopes);
    }

    [Theory]
    [InlineData("connector")]
    [InlineData("principal")]
    [InlineData("profile")]
    [InlineData("device")]
    public void WrongAuthorityHandleIsRejected(string field)
    {
        var fixture = Fixture();
        var changed = fixture with
        {
            Context = field switch
            {
                "connector" => fixture.Context with { ConnectorId = "another-connector" },
                "principal" => fixture.Context with { PrincipalHandle = Handle("principal", "another-principal") },
                "profile" => fixture.Context with { ProfileId = "another-profile" },
                _ => fixture.Context with { DeviceInstallationHandle = Handle("device", "another-device") }
            }
        };

        Assert.Throws<InvalidOperationException>(() => KaevoMemberMediaCapabilityVerifier.Verify(
            Capability(fixture, new[] { "metadata.read", "progress.read" }),
            changed.Context,
            changed.Keys,
            Issuer,
            Now));
    }

    [Fact]
    public void ChangedOrMissingBindingNeverFallsBackToTheOwnerIdentity()
    {
        var fixture = Fixture();
        var token = Capability(fixture, new[] { "metadata.read", "progress.read" });

        Assert.Throws<InvalidOperationException>(() => KaevoMemberMediaCapabilityVerifier.Verify(
            token,
            fixture.Context with { BindingsJson = JsonSerializer.Serialize(new Dictionary<string, string> { ["owner"] = User }) },
            fixture.Keys,
            Issuer,
            Now));
        Assert.Throws<InvalidOperationException>(() => KaevoMemberMediaCapabilityVerifier.Verify(
            token,
            fixture.Context with { BindingsJson = null },
            fixture.Keys,
            Issuer,
            Now));
    }

    [Fact]
    public void ChangedBindingRevisionAndExpiredCapabilityAreRejected()
    {
        var fixture = Fixture();
        var changedBinding = JsonSerializer.Serialize(new Dictionary<string, string>
        {
            [Profile] = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        });

        Assert.Throws<InvalidOperationException>(() => KaevoMemberMediaCapabilityVerifier.Verify(
            Capability(fixture, new[] { "metadata.read", "progress.read" }),
            fixture.Context with { BindingsJson = changedBinding }, fixture.Keys, Issuer, Now));
        Assert.Throws<InvalidOperationException>(() => KaevoMemberMediaCapabilityVerifier.Verify(
            Capability(fixture, new[] { "metadata.read", "progress.read" }, exp: Now - 1),
            fixture.Context, fixture.Keys, Issuer, Now));
    }

    [Fact]
    public void MissingScopeMalformedAndRawProviderClaimsAreRejected()
    {
        var fixture = Fixture();
        Assert.Throws<InvalidOperationException>(() => KaevoMemberMediaCapabilityVerifier.Verify(
            Capability(fixture, new[] { "metadata.read" }), fixture.Context, fixture.Keys, Issuer, Now));
        Assert.Throws<InvalidOperationException>(() => KaevoMemberMediaCapabilityVerifier.Verify(
            "not-a-capability", fixture.Context, fixture.Keys, Issuer, Now));
        Assert.Throws<InvalidOperationException>(() => KaevoMemberMediaCapabilityVerifier.Verify(
            Capability(fixture, new[] { "metadata.read", "progress.read" }, extra: new Dictionary<string, object> { ["jellyfin_user_id"] = User }),
            fixture.Context, fixture.Keys, Issuer, Now));
    }

    [Fact]
    public void DisabledOrDeletedJellyfinUsersAreNotUsable()
    {
        Assert.False(KaevoMemberMediaUserState.IsActive(JsonSerializer.SerializeToElement(new { Policy = new { IsDisabled = true } })));
        Assert.False(KaevoMemberMediaUserState.IsActive(default));
        Assert.True(KaevoMemberMediaUserState.IsActive(JsonSerializer.SerializeToElement(new { Id = User, Policy = new { IsDisabled = false } })));
    }

    [Fact]
    public void MemberScopesAreSeparatedAndClientSelectedUsersAreRejected()
    {
        var request = Request("GET", "/kaevo/internal/main-snapshot");
        Assert.Equal(new[] { "metadata.read", "progress.read" }, KaevoCloudConnectorService.RequiredMemberScopes(request));
        Assert.Equal(new[] { "search.read" }, KaevoCloudConnectorService.RequiredMemberScopes(Request("POST", "/commands/jellyfin.search", "jellyfin.search")));
        Assert.Throws<InvalidOperationException>(() => KaevoCloudConnectorService.EnsureMemberRequestTargetsExactUser(
            Request("GET", "/Users/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/Items"),
            User.Replace("-", string.Empty, StringComparison.Ordinal)));
    }

    [Fact]
    public void ServiceRequiresV3SignedCapabilityBeforeMemberOperation()
    {
        var fixture = Fixture();
        var request = Request("GET", "/kaevo/internal/main-snapshot") with
        {
            MemberMediaCapability = Capability(fixture, new[] { "metadata.read", "progress.read" }),
            MemberMediaContext = new CloudMemberMediaContext(
                fixture.Context.PrincipalHandle,
                fixture.Context.HouseholdHandle,
                fixture.Context.DeviceInstallationHandle)
        };

        Assert.Equal(User.Replace("-", string.Empty, StringComparison.Ordinal),
            KaevoCloudConnectorService.RequireMemberMediaCapability(true, Connector, fixture.Context.BindingsJson, fixture.Keys, Issuer, request, Now).JellyfinUserId);
        Assert.Throws<InvalidOperationException>(() => KaevoCloudConnectorService.RequireMemberMediaCapability(
            true, Connector, fixture.Context.BindingsJson, fixture.Keys, Issuer,
            request with { ProfileProviderBinding = new CloudProfileProviderBinding("jellyfin", Connector, User) },
            Now));
    }

    private static CapabilityFixture Fixture()
    {
        var bindings = JsonSerializer.Serialize(new Dictionary<string, string> { [Profile] = User });
        return new CapabilityFixture(
            new KaevoMemberMediaCapabilityContext(
                Connector,
                Profile,
                Handle("principal", "principal-member"),
                Handle("household", "household-member"),
                Handle("device", "device-installation-member"),
                new[] { "metadata.read", "progress.read" },
                bindings),
            JsonSerializer.Serialize(new Dictionary<string, string>
            {
                ["member-test-key"] = KaevoPairingV3Crypto.Base64Url(KaevoPairingV3Crypto.PublicKeyFromSeed(SigningSeed))
            }));
    }

    private static CloudRequest Request(string method, string path, string? operation = null) =>
        new("member-request", method, "jellyfin", path, null, operation, null, Profile);

    private static string Capability(
        CapabilityFixture fixture,
        IReadOnlyCollection<string> scopes,
        long? exp = null,
        IReadOnlyDictionary<string, object>? extra = null)
    {
        var payload = new SortedDictionary<string, object>(StringComparer.Ordinal)
        {
            ["aud"] = KaevoMemberMediaCapabilityVerifier.Audience,
            ["binding_handle"] = KaevoProfileJellyfinBindingStore.MemberBindingHandle(Profile, User),
            ["binding_revision"] = KaevoProfileJellyfinBindingStore.MemberBindingRevision(Profile, User),
            ["capability_type"] = "member_media",
            ["connector_handle"] = Handle("connector", Connector),
            ["device_installation_handle"] = fixture.Context.DeviceInstallationHandle,
            ["exp"] = exp ?? Now + 120,
            ["household_handle"] = fixture.Context.HouseholdHandle,
            ["iat"] = Now - 5,
            ["iss"] = Issuer,
            ["jti"] = "member-capability-grant-0001",
            ["nbf"] = Now - 10,
            ["principal_handle"] = fixture.Context.PrincipalHandle,
            ["profile_handle"] = Handle("profile", Profile),
            ["protocol"] = KaevoPairingV3Crypto.Protocol,
            ["scope"] = scopes,
            ["v"] = 1
        };
        if (extra is not null)
        {
            foreach (var pair in extra) payload[pair.Key] = pair.Value;
        }
        var header = new SortedDictionary<string, object>(StringComparer.Ordinal)
        {
            ["alg"] = "EdDSA", ["kid"] = "member-test-key", ["typ"] = KaevoMemberMediaCapabilityVerifier.Type
        };
        var encodedHeader = Base64Url(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(header)));
        var encodedPayload = Base64Url(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload)));
        return encodedHeader + "." + encodedPayload + "." + KaevoPairingV3Crypto.Sign(
            SigningSeed, Encoding.ASCII.GetBytes(encodedHeader + "." + encodedPayload));
    }

    private static string Handle(string domain, string value) => KaevoProfileJellyfinBindingStore.OpaqueHandle(domain, value);
    private static string Base64Url(byte[] value) => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    private sealed record CapabilityFixture(KaevoMemberMediaCapabilityContext Context, string Keys);
}
