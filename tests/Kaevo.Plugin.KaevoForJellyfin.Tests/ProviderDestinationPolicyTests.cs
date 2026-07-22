using System.Net;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class ProviderDestinationPolicyTests
{
    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("::1")]
    [InlineData("0.0.0.0")]
    [InlineData("::")]
    [InlineData("169.254.169.254")]
    [InlineData("224.0.0.1")]
    [InlineData("ff02::1")]
    [InlineData("8.8.8.8")]
    [InlineData("2606:4700:4700::1111")]
    [InlineData("::ffff:127.0.0.1")]
    public async Task ProhibitedAndPublicDestinationsFail(string address)
    {
        var policy = Policy(address);
        await Assert.ThrowsAnyAsync<ArgumentException>(() => policy.ApproveAsync("sonarr", "http://provider.test:8989", default));
    }

    [Theory]
    [InlineData("http://user:pass@provider.test:8989")]
    [InlineData("file://provider.test:8989/path")]
    [InlineData("http://provider.test:8989/path#fragment")]
    [InlineData("http://2130706433:8989")]
    [InlineData("http://0x7f000001:8989")]
    [InlineData("http://0177.0.0.1:8989")]
    [InlineData("http://provider.test:22")]
    public async Task MalformedEmbeddedAndAlternateDestinationsFail(string value)
    {
        await Assert.ThrowsAnyAsync<ArgumentException>(() => Policy("192.168.40.10").ApproveAsync("sonarr", value, default));
    }

    [Fact]
    public async Task PrivateDestinationIsNormalizedAndPinnedToEveryResolvedAddress()
    {
        var policy = new KaevoProviderDestinationPolicy(new FakeDns("192.168.40.11", "192.168.40.10"));
        var approved = await policy.ApproveAsync("sonarr", "HTTP://Provider.Test.:8989/base", default);
        Assert.Equal("http://provider.test:8989/base/", approved.BaseUri.ToString());
        Assert.Equal(new[] { "192.168.40.10", "192.168.40.11" }, approved.Addresses);
    }

    [Fact]
    public async Task AdministratorApprovedHighDockerPortIsPinned()
    {
        var approved = await Policy("192.168.40.10")
            .ApproveAsync("seerr", "http://provider.test:30357", default);

        Assert.Equal("http://provider.test:30357/", approved.BaseUri.ToString());
        Assert.Equal(new[] { "192.168.40.10" }, approved.Addresses);
    }

    [Fact]
    public async Task LegacyProviderWithoutPinnedAddressesRequiresReapproval()
    {
        var secret = new KaevoLocalProviderSecret(
            "http://provider.test:30357",
            "key",
            true,
            Array.Empty<string>());

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            Policy("192.168.40.10").RevalidateAsync(
                "seerr",
                secret,
                new Uri("http://provider.test:30357/api/v1/status"),
                default));

        Assert.Equal("providerDestinationReapprovalRequired", error.Message);
    }

    [Fact]
    public async Task ReorderedApprovedDnsSetProducesTheSameDeterministicConnectionOrder()
    {
        var secret = new KaevoLocalProviderSecret("http://provider.test:8989", "key", true, new[] { "192.168.40.10", "192.168.40.11" });
        var first = await new KaevoProviderDestinationPolicy(new FakeDns("192.168.40.11", "192.168.40.10"))
            .RevalidateAsync("sonarr", secret, new Uri("http://provider.test:8989/api/v3/system/status"), default);
        var second = await new KaevoProviderDestinationPolicy(new FakeDns("192.168.40.10", "192.168.40.11"))
            .RevalidateAsync("sonarr", secret, new Uri("http://provider.test:8989/api/v3/system/status"), default);
        Assert.Equal(first, second);
        Assert.Equal("192.168.40.10", first[0].ToString());
    }

    [Fact]
    public async Task MixedDnsResultFailsAndRebindingRequiresReapproval()
    {
        await Assert.ThrowsAnyAsync<ArgumentException>(() =>
            new KaevoProviderDestinationPolicy(new FakeDns("192.168.40.10", "8.8.8.8"))
                .ApproveAsync("sonarr", "http://provider.test:8989", default));
        var secret = new KaevoLocalProviderSecret("http://provider.test:8989", "key", true, new[] { "192.168.40.10" });
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new KaevoProviderDestinationPolicy(new FakeDns("192.168.40.11"))
                .RevalidateAsync("sonarr", secret, new Uri("http://provider.test:8989/api/v3/system/status"), default));
    }

    [Fact]
    public void RedirectMustRemainSameOriginBaseAndProtocol()
    {
        var policy = Policy("192.168.40.10");
        var secret = new KaevoLocalProviderSecret("https://provider.test:443/base", "key", true, new[] { "192.168.40.10" });
        var from = new Uri("https://provider.test/base/start");
        Assert.Equal("https://provider.test/base/next", policy.ValidateRedirect("sonarr", secret, from, new Uri("next", UriKind.Relative)).ToString());
        Assert.Throws<InvalidOperationException>(() => policy.ValidateRedirect("sonarr", secret, from, new Uri("https://192.168.40.11/base")));
        Assert.Throws<InvalidOperationException>(() => policy.ValidateRedirect("sonarr", secret, from, new Uri("http://provider.test/base")));
        Assert.Throws<InvalidOperationException>(() => policy.ValidateRedirect("sonarr", secret, from, new Uri("https://provider.test/other")));
        Assert.Throws<InvalidOperationException>(() => policy.ValidateRedirect("sonarr", secret, from, new Uri("https://provider.test/base/%2e%2e/admin")));
        Assert.Throws<InvalidOperationException>(() => policy.ValidateRedirect("sonarr", secret, from, new Uri("https://provider.test/base/%2fadmin")));
    }

    [Fact]
    public async Task SecurityStageAllowsOnlyExactMockServiceName()
    {
        var policy = new KaevoProviderDestinationPolicy(new FakeDns("172.28.0.3"), true, new[] { "mock-sonarr" });
        var ok = await policy.ApproveAsync("sonarr", "http://mock-sonarr:8989", default);
        Assert.Equal("mock-sonarr", ok.BaseUri.Host);
        await Assert.ThrowsAnyAsync<ArgumentException>(() => policy.ApproveAsync("sonarr", "http://unrelated:8989", default));
    }

    private static KaevoProviderDestinationPolicy Policy(params string[] values) => new(new FakeDns(values));
    private sealed class FakeDns(params string[] values) : IKaevoDnsResolver
    {
        public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken) =>
            Task.FromResult(values.Select(IPAddress.Parse).ToArray());
    }
}
