using System.Net;
using System.Runtime.CompilerServices;
using System.Text.Json;
using Google.Cloud.Firestore.V1;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class ConnectorRecoveryTests
{
    private const string Server = "123456781234123412341234567890ab";
    private const string Channel = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string Epoch = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    private const string DocumentPath = "projects/demo-kaevo-migration/databases/(default)/documents/connector_signals/" + Channel;
    private sealed class Handler(Func<HttpRequestMessage, HttpResponseMessage> reply) : HttpMessageHandler
    {
        internal int Calls;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        { token.ThrowIfCancellationRequested(); Calls++; return Task.FromResult(reply(request)); }
    }
    private static HttpResponseMessage Json(object value, HttpStatusCode status = HttpStatusCode.OK) =>
        new(status) { Content = new StringContent(JsonSerializer.Serialize(value)) };

    [Theory]
    [InlineData("success", 2, true)]
    [InlineData("wrong-server", 1, false)]
    [InlineData("revoked", 1, false)]
    [InlineData("same-key", 1, false)]
    [InlineData("explicit", 0, false)]
    [InlineData("candidate-denied", 2, false)]
    [InlineData("binding-changed", 2, false)]
    [InlineData("redirect", 1, false)]
    [InlineData("oversized", 1, false)]
    public async Task CredentialRecoveryPreservesBoundaries(string mode, int calls, bool repaired)
    {
        var saved = false;
        var lookedUp = 0;
        var handler = new Handler(request =>
        {
            Assert.Equal("verified.test", request.RequestUri!.Host);
            Assert.Equal(HttpMethod.Get, request.Method);
            if (request.RequestUri.AbsolutePath.EndsWith("/Public"))
            {
                Assert.Null(request.Headers.Authorization);
                if (mode == "redirect") return Json(new { }, HttpStatusCode.Redirect);
                if (mode == "oversized") return Json(new { Id = Server, Padding = new string('a', 65536) });
                return Json(new { Id = mode == "wrong-server" ? Guid.NewGuid().ToString("N") : Server });
            }
            Assert.Equal("/jellyfin/System/Info", request.RequestUri.AbsolutePath);
            Assert.Contains("Token=\"owned-key\"", request.Headers.Authorization!.Parameter);
            return Json(new { Id = Server }, mode == "candidate-denied" ? HttpStatusCode.Unauthorized : HttpStatusCode.OK);
        });
        using var client = new HttpClient(handler);
        var recovery = new KaevoJellyfinCredentialRecovery();
        var result = await recovery.RecoverAsync(new Uri("http://verified.test/jellyfin/"), Server, "old-key", mode == "explicit",
            _ => { lookedUp++; return Task.FromResult(mode == "revoked" ? "" : mode == "same-key" ? "old-key" : "owned-key"); },
            (key, _) => { saved = mode != "binding-changed"; return Task.FromResult(saved); }, default, client);
        Assert.Equal(repaired ? "owned-key" : null, result);
        Assert.Equal(repaired, saved);
        Assert.Equal(calls, handler.Calls);
        if (mode is "wrong-server" or "explicit" or "redirect" or "oversized") Assert.Equal(0, lookedUp);
        // Repeated failing probes cannot stampede the server.
        await recovery.RecoverAsync(new Uri("http://verified.test/"), Server, "old-key", mode == "explicit",
            _ => throw new Exception("must not retry"), (_, _) => throw new Exception("must not save"), default, client);
        Assert.Equal(calls, handler.Calls);
    }

    [Theory]
    [InlineData("same", true)]
    [InlineData("credential-changed", false)]
    [InlineData("connector-changed", false)]
    [InlineData("grant-changed", false)]
    [InlineData("other-provider-changed", true)]
    public async Task CredentialSaveIsAtomicAndPreservesUnrelatedSecrets(string change, bool accepted)
    {
        var dir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N")); Directory.CreateDirectory(dir);
        try
        {
            var store = new KaevoSecretStore(Path.Combine(dir, "secrets.json"), NullLogger<KaevoSecretStore>.Instance);
            var original = new KaevoConnectorSecrets("connector", "grant", "rejected", "sonarr", "key");
            await store.WriteAsync(original, default);
            var current = change switch {
                "credential-changed" => original with { JellyfinApiKey = "manual-repair" },
                "connector-changed" => original with { ConnectorToken = "another" },
                "grant-changed" => original with { PlaybackGrantKey = "another" },
                "other-provider-changed" => original with { SonarrApiKey = "new-sonarr-key" }, _ => original };
            await store.WriteAsync(current, default);
            Assert.Equal(accepted, await store.ReplaceRejectedJellyfinKeyAsync(original, "owned-key", default));
            Assert.Equal(accepted ? current with { JellyfinApiKey = "owned-key" } : current, await store.ReadAsync(default));
        }
        finally { Directory.Delete(dir, true); }
    }

    private static async IAsyncEnumerable<string> Stalled(Action disposed,
        [EnumeratorCancellation] CancellationToken token)
    {
        try { await Task.Delay(Timeout.InfiniteTimeSpan, token); yield break; }
        finally { disposed(); }
    }
    private static async IAsyncEnumerable<string> Failed(string failure, [EnumeratorCancellation] CancellationToken token)
    {
        await Task.Yield(); token.ThrowIfCancellationRequested();
        throw new InvalidOperationException(failure);
#pragma warning disable CS0162
        yield break;
#pragma warning restore CS0162
    }

    [Fact]
    public async Task StalledLiveReadIsDisposedBeforeExactChannelFallback()
    {
        var disposed = false;
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        var reads = 0;
        await using var reader = FirebaseControlReadFallback.ReadAsync(
            t => Stalled(() => disposed = true, t), _ => { Assert.True(disposed); reads++; return Task.FromResult<IReadOnlyList<string>>(["r1"]); },
            () => TimeSpan.FromSeconds(20), DateTimeOffset.UtcNow.AddSeconds(10), stop.Token,
            TimeSpan.FromMilliseconds(10), TimeSpan.FromMilliseconds(10)).GetAsyncEnumerator();
        Assert.True(await reader.MoveNextAsync()); Assert.Equal("r1", reader.Current); Assert.Equal(1, reads);
    }

    private static async IAsyncEnumerable<string> RacingHint([EnumeratorCancellation] CancellationToken token)
    {
        try { await Task.Delay(Timeout.InfiniteTimeSpan, token); }
        catch (OperationCanceledException) { }
        // A valid snapshot can finish at the same moment the watchdog switches.
        yield return "racing-request";
    }

    [Fact]
    public async Task AHintArrivingDuringTransportHandoffIsNotLost()
    {
        await using var reader = FirebaseControlReadFallback.ReadAsync(t => RacingHint(t),
            _ => Task.FromResult<IReadOnlyList<string>>([]), () => TimeSpan.FromSeconds(20),
            DateTimeOffset.UtcNow.AddSeconds(10), default, TimeSpan.FromMilliseconds(10)).GetAsyncEnumerator();
        Assert.True(await reader.MoveNextAsync());
        Assert.Equal("racing-request", reader.Current);
    }

    [Theory]
    [InlineData("firebaseControlAccessDenied")]
    [InlineData("firebaseControlSignalInvalid")]
    [InlineData("firebaseControlAdmissionInvalid")]
    [InlineData("firebaseControlTargetLost")]
    public async Task AuthorizationOrValidationFailuresNeverTriggerFallback(string failure)
    {
        await using var reader = FirebaseControlReadFallback.ReadAsync(t => Failed(failure, t),
            _ => throw new Exception("fallback forbidden"), () => TimeSpan.Zero,
            DateTimeOffset.UtcNow.AddSeconds(10), default).GetAsyncEnumerator();
        Assert.Equal(failure, (await Assert.ThrowsAsync<InvalidOperationException>(async () => await reader.MoveNextAsync())).Message);
    }

    [Theory]
    [InlineData("firebaseControlTransportFailed")]
    [InlineData("firebaseControlDisconnected")]
    public async Task TransportFailureRecoversWithoutWaitingForLease(string failure)
    {
        await using var reader = FirebaseControlReadFallback.ReadAsync(t => Failed(failure, t),
            _ => Task.FromResult<IReadOnlyList<string>>(["recovered"]), () => TimeSpan.Zero,
            DateTimeOffset.UtcNow.AddSeconds(10), default).GetAsyncEnumerator();
        Assert.True(await reader.MoveNextAsync()); Assert.Equal("recovered", reader.Current);
    }

    [Theory]
    [InlineData("valid")]
    [InlineData("wrong-channel")]
    [InlineData("wrong-epoch")]
    [InlineData("denied")]
    [InlineData("redirect")]
    [InlineData("oversized")]
    public async Task RestFallbackReadsOnlyExactDocumentAndValidatesWholeResponse(string mode)
    {
        var document = new Document { Name = mode == "wrong-channel" ? DocumentPath + "x" : DocumentPath,
            Fields = { ["epoch"] = new Value { StringValue = mode == "wrong-epoch" ? "wrong" : Epoch },
                ["revision"] = new Value { IntegerValue = 1 },
                ["request_ids"] = new Value { ArrayValue = new ArrayValue { Values = { new Value { StringValue = "r1" } } } } } };
        using var client = new HttpClient(new Handler(request =>
        {
            Assert.Equal("https://firestore.googleapis.com/v1/" + DocumentPath, request.RequestUri!.AbsoluteUri);
            Assert.Equal("Bearer", request.Headers.Authorization!.Scheme);
            Assert.Equal("test.token", request.Headers.Authorization.Parameter);
            Assert.Equal(HttpMethod.Get, request.Method);
            return new HttpResponseMessage(mode == "denied" ? HttpStatusCode.Forbidden : mode == "redirect" ? HttpStatusCode.Redirect : HttpStatusCode.OK)
                { Content = new StringContent(mode == "oversized" ? new string('x', 131073) : document.ToString()) };
        }));
        var state = new FirebaseFirestoreSignalState(DocumentPath, Epoch);
        var callbacks = 0;
        Task<IReadOnlyList<string>> Read() => FirebaseControlReadFallback.ReadDocumentAsync("demo-kaevo-migration", Channel, Epoch,
            "test.token", DateTimeOffset.UtcNow.AddSeconds(30), state, _ => callbacks++, default, client);
        if (mode == "valid")
        {
            Assert.Equal(new[] { "r1" }, await Read());
            Assert.Empty(await Read()); Assert.Equal(2, callbacks);
        }
        else { await Assert.ThrowsAsync<InvalidOperationException>(Read); Assert.Equal(0, callbacks); }
    }

    [Fact]
    public async Task CancellationNeverStartsFallback()
    {
        using var stop = new CancellationTokenSource(); stop.Cancel();
        await using var reader = FirebaseControlReadFallback.ReadAsync(t => Stalled(() => {}, t),
            _ => throw new Exception("fallback forbidden"), () => TimeSpan.Zero,
            DateTimeOffset.UtcNow.AddSeconds(10), stop.Token).GetAsyncEnumerator();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await reader.MoveNextAsync());
    }
}
