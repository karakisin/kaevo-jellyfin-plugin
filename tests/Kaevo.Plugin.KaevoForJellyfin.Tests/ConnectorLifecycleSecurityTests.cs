using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class ConnectorLifecycleSecurityTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "kaevo-lifecycle-" + Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task IdentityAndServerBindingSurviveRestartWithOwnerOnlyPermissions()
    {
        var firstStore = Store();
        var first = await firstStore.LoadOrInitializeAsync();
        var second = await Store().LoadOrInitializeAsync();
        Assert.Equal(first.ServerId, second.ServerId);
        Assert.StartsWith("srv_", first.ServerId);
        Assert.Equal("security-stage", first.Environment);
        if (!OperatingSystem.IsWindows())
        {
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(firstStore.StatePath));
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, File.GetUnixFileMode(firstStore.DirectoryPath));
        }
        Assert.DoesNotContain("PRIVATE KEY", await File.ReadAllTextAsync(firstStore.StatePath));
    }

    [Fact]
    public async Task FailedRotationPreservesCurrentKeyAndVersion()
    {
        var store = Store();
        await store.LoadOrInitializeAsync();
        var (_, pair) = await store.BeginTransitionAsync("pair");
        pair.Dispose();
        var active = await store.CommitTransitionAsync("connector-1", 1);
        var original = await File.ReadAllBytesAsync(Path.Combine(store.DirectoryPath, active.CurrentKeyFile));
        var (_, proposed) = await store.BeginTransitionAsync("rotate");
        proposed.Dispose();
        var restored = await store.AbortTransitionAsync();
        Assert.Equal(1, restored.CredentialVersion);
        Assert.Equal(original, await File.ReadAllBytesAsync(Path.Combine(store.DirectoryPath, restored.CurrentKeyFile)));
    }

    [Fact]
    public async Task RotationIsMonotonicAndRemovesSupersededPrivateKey()
    {
        var store = Store();
        await store.LoadOrInitializeAsync();
        var (_, pair) = await store.BeginTransitionAsync("pair"); pair.Dispose();
        var one = await store.CommitTransitionAsync("connector-1", 1);
        var oldPath = Path.Combine(store.DirectoryPath, one.CurrentKeyFile);
        var (_, rotate) = await store.BeginTransitionAsync("rotate"); rotate.Dispose();
        await Assert.ThrowsAsync<InvalidOperationException>(() => store.CommitTransitionAsync("connector-1", 3));
        var two = await store.CommitTransitionAsync("connector-1", 2);
        Assert.Equal(2, two.CredentialVersion);
        Assert.False(File.Exists(oldPath));
    }

    [Fact]
    public void DpopIsEs256P1363AndBoundToExactRequest()
    {
        Directory.CreateDirectory(_directory);
        using var identity = KaevoConnectorIdentity.LoadOrCreate(Path.Combine(_directory, "key.pem"));
        var uri = new Uri("https://cloud.example/v1/home-connectors/c/heartbeat");
        var proof = identity.CreateProof(HttpMethod.Post, uri, 1000, "fixed-jti");
        var parts = proof.Split('.');
        Assert.Equal(3, parts.Length);
        using var header = JsonDocument.Parse(Decode(parts[0]));
        using var payload = JsonDocument.Parse(Decode(parts[1]));
        Assert.Equal("ES256", header.RootElement.GetProperty("alg").GetString());
        Assert.Equal("dpop+jwt", header.RootElement.GetProperty("typ").GetString());
        Assert.Equal("POST", payload.RootElement.GetProperty("htm").GetString());
        Assert.Equal(uri.AbsoluteUri, payload.RootElement.GetProperty("htu").GetString());
        Assert.Equal(1000, payload.RootElement.GetProperty("iat").GetInt64());
        Assert.Equal("fixed-jti", payload.RootElement.GetProperty("jti").GetString());
        Assert.Equal(64, Decode(parts[2]).Length);
    }

    [Fact]
    public async Task ConnectorRequestUsesDpopAndVersionWithoutBearerOrPrivateMaterial()
    {
        var store = Store();
        await store.LoadOrInitializeAsync();
        var (_, pair) = await store.BeginTransitionAsync("pair"); pair.Dispose();
        await store.CommitTransitionAsync("connector-1", 1);
        var handler = new CaptureHandler();
        var client = new KaevoConnectorLifecycleClient(store, new HttpClient(handler));
        using var response = await client.SendConnectorAsync(new Uri("https://cloud.example"), HttpMethod.Post, "/v1/home-connectors/register", new { connector_id = "connector-1" }, default);
        Assert.Null(handler.Request!.Headers.Authorization);
        Assert.True(handler.Request.Headers.Contains("DPoP"));
        Assert.Equal("1", handler.Request.Headers.GetValues("X-Kaevo-Credential-Version").Single());
        Assert.DoesNotContain("PRIVATE", handler.Body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task PairingUsesV2ExchangeAndNeverSendsPrivateKeys()
    {
        var store = Store();
        var handler = new SequenceHandler(
            "{\"connector_id\":\"connector-1\",\"intent_id\":\"intent-1\",\"pairing_code\":\"ABCD-1234-EF56\"}",
            "{\"connector_id\":\"connector-1\",\"server_id\":\"ignored\",\"credential_version\":1}");
        var client = new KaevoConnectorLifecycleClient(store, new HttpClient(handler));
        var result = await client.PairAsync(new Uri("https://cloud.example"), "owner-token-value", "profile-1", default);
        Assert.Equal(1, result.CredentialVersion);
        Assert.Equal(new[] { "/v1/home-connectors/pairing/start", "/v2/home-connectors/pairing/exchange" }, handler.Requests.Select(r => r.Path));
        Assert.DoesNotContain(handler.Requests, request => request.Path == "/v1/home-connectors/pairing/exchange");
        Assert.All(handler.Requests, request => Assert.DoesNotContain("PRIVATE", request.Body, StringComparison.OrdinalIgnoreCase));
        Assert.Contains("DPoP", handler.Requests[0].Headers);
        Assert.Contains("DPoP-Recovery", handler.Requests[0].Headers);
        Assert.Contains("DPoP", handler.Requests[1].Headers);
        Assert.DoesNotContain("connector_token", string.Join(' ', handler.Requests.Select(r => r.Body)), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RestartAfterCloudActivationPromotesOnlyTheAcceptedPendingKey()
    {
        var store = Store();
        await store.LoadOrInitializeAsync();
        var (_, proposed) = await store.BeginTransitionAsync("pair"); proposed.Dispose();
        await store.BindPendingConnectorAsync("connector-1");
        var before = await store.LoadOrInitializeAsync();
        var handler = new SequenceHandler("{}");
        var client = new KaevoConnectorLifecycleClient(Store(), new HttpClient(handler));

        var reconciled = await client.ReconcilePendingAsync(new Uri("https://cloud.example"), "profile-1", default);

        Assert.Equal("active", reconciled.State);
        Assert.Equal(1, reconciled.CredentialVersion);
        Assert.Equal("connector-1", reconciled.ConnectorId);
        Assert.Empty(reconciled.PendingKeyFile);
        Assert.NotEqual(before.PendingKeyFile, reconciled.CurrentKeyFile);
        Assert.Contains("DPoP", handler.Requests.Single().Headers);
    }

    [Fact]
    public async Task RestartBeforeCloudActivationKeepsCurrentKeyAndVersion()
    {
        var store = Store();
        await store.LoadOrInitializeAsync();
        var (_, pair) = await store.BeginTransitionAsync("pair"); pair.Dispose();
        var active = await store.CommitTransitionAsync("connector-1", 1);
        var currentBytes = await File.ReadAllBytesAsync(Path.Combine(store.DirectoryPath, active.CurrentKeyFile));
        var (_, proposed) = await store.BeginTransitionAsync("rotate"); proposed.Dispose();
        var handler = new StatusSequenceHandler(HttpStatusCode.Unauthorized, HttpStatusCode.OK);
        var client = new KaevoConnectorLifecycleClient(Store(), new HttpClient(handler));

        var reconciled = await client.ReconcilePendingAsync(new Uri("https://cloud.example"), "profile-1", default);

        Assert.Equal("active", reconciled.State);
        Assert.Equal(1, reconciled.CredentialVersion);
        Assert.Empty(reconciled.PendingKeyFile);
        Assert.Equal(currentBytes, await File.ReadAllBytesAsync(Path.Combine(store.DirectoryPath, reconciled.CurrentKeyFile)));
        Assert.Equal(new[] { "2", "1" }, handler.Versions);
    }

    [Fact]
    public async Task UnsupportedFutureLifecycleSchemaFailsClosedWithoutErasingState()
    {
        var store = Store();
        var state = await store.LoadOrInitializeAsync();
        var original = await File.ReadAllTextAsync(store.StatePath);
        var future = original.Replace("\"schemaVersion\":1", "\"schemaVersion\":2", StringComparison.Ordinal);
        await File.WriteAllTextAsync(store.StatePath, future);

        await Assert.ThrowsAsync<InvalidOperationException>(() => Store().LoadOrInitializeAsync());
        Assert.Equal(future, await File.ReadAllTextAsync(store.StatePath));
        Assert.Contains(state.ServerId, future);
    }

    [Fact]
    public async Task FailedCloudRotationPreservesAcceptedVersionAndKey()
    {
        var store = Store();
        await store.LoadOrInitializeAsync();
        var (_, pair) = await store.BeginTransitionAsync("pair"); pair.Dispose();
        var one = await store.CommitTransitionAsync("connector-1", 1);
        var bytes = await File.ReadAllBytesAsync(Path.Combine(store.DirectoryPath, one.CurrentKeyFile));
        var handler = new SequenceHandler("{}") { StatusCode = HttpStatusCode.Unauthorized };
        var client = new KaevoConnectorLifecycleClient(store, new HttpClient(handler));
        await Assert.ThrowsAsync<InvalidOperationException>(() => client.RotateAsync(new Uri("https://cloud.example"), "owner-token-value", "profile-1", default));
        var restored = await store.LoadOrInitializeAsync();
        Assert.Equal(1, restored.CredentialVersion);
        Assert.Equal(bytes, await File.ReadAllBytesAsync(Path.Combine(store.DirectoryPath, restored.CurrentKeyFile)));
        Assert.Empty(restored.PendingKeyFile);
    }

    [Fact]
    public async Task EnvironmentChangeAndLegacyUnenrolledStateFailClosed()
    {
        await Store().LoadOrInitializeAsync();
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new KaevoConnectorLifecycleStore(_directory, "production").LoadOrInitializeAsync());
        var state = await Store().LoadOrInitializeAsync();
        Assert.Throws<InvalidOperationException>(() => Store().LoadCurrent(state));
    }

    private KaevoConnectorLifecycleStore Store() => new(_directory, "security-stage");
    private static byte[] Decode(string value) => Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/') + new string('=', (4 - value.Length % 4) % 4));
    public void Dispose() { if (Directory.Exists(_directory)) Directory.Delete(_directory, true); }

    private sealed class CaptureHandler : HttpMessageHandler
    {
        public HttpRequestMessage? Request { get; private set; }
        public string Body { get; private set; } = "";
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Request = request;
            Body = request.Content is null ? "" : await request.Content.ReadAsStringAsync(cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{}") };
        }
    }

    private sealed class StatusSequenceHandler(params HttpStatusCode[] statuses) : HttpMessageHandler
    {
        private int _index;
        public List<string> Versions { get; } = new();
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Versions.Add(request.Headers.GetValues("X-Kaevo-Credential-Version").Single());
            var status = statuses[Math.Min(_index++, statuses.Length - 1)];
            return Task.FromResult(new HttpResponseMessage(status) { Content = new StringContent("{}") });
        }
    }

    private sealed record SeenRequest(string Path, string Body, HashSet<string> Headers);
    private sealed class SequenceHandler(params string[] responses) : HttpMessageHandler
    {
        private int _index;
        public HttpStatusCode StatusCode { get; set; } = HttpStatusCode.OK;
        public List<SeenRequest> Requests { get; } = new();
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var body = request.Content is null ? "" : await request.Content.ReadAsStringAsync(cancellationToken);
            Requests.Add(new SeenRequest(request.RequestUri!.AbsolutePath, body, request.Headers.Select(h => h.Key).ToHashSet(StringComparer.OrdinalIgnoreCase)));
            var value = responses[Math.Min(_index++, responses.Length - 1)];
            return new HttpResponseMessage(StatusCode) { Content = new StringContent(value, Encoding.UTF8, "application/json") };
        }
    }
}
