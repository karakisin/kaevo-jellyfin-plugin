using System.Net;
using System.Net.WebSockets;
using System.Reflection;
using System.Text;
using System.Text.Json;
using Kaevo.Plugin.KaevoForJellyfin.Configuration;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

// Actual retained handler + V3 verifier/resolver + loopback WebSocket writes.
// HTTP provider is an in-memory handler: never touches Jellyfin or user data.
public sealed class FirebaseRelayHandlerActivityTests
{
    private sealed class Provider : HttpMessageHandler
    {
        internal int Calls;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            Calls++;
            Assert.Equal("synthetic-jellyfin.invalid", request.RequestUri!.Host);
            Assert.Contains("mediaSourceId=source-1", request.RequestUri.Query);
            Assert.Contains("playSessionId=session-1", request.RequestUri.Query);
            Assert.Contains("deviceId=ios-device-1", request.RequestUri.Query);
            Assert.Contains("StartTimeTicks=987654321", request.RequestUri.Query);
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            { Content = new StringContent("#EXTM3U\n#EXT-X-ENDLIST\n", Encoding.UTF8, "application/vnd.apple.mpegurl") };
            return Task.FromResult(response);
        }
    }
    private sealed class Activity : KaevoCloudConnectorService.IRelayRequestActivity
    {
        internal int Bodies, Disposals;
        public void RecordBodyProgress() => Bodies++;
        public void Dispose() => Disposals++;
    }

    [Theory]
    [InlineData("body", 1, 1)]
    [InlineData("head", 1, 0)]
    [InlineData("wrong-signature", 0, 0)]
    [InlineData("wrong-item", 0, 0)]
    [InlineData("wrong-device", 0, 0)]
    [InlineData("wrong-range", 0, 0)]
    public async Task OnlyValidatedRequestAndSuccessfullySentBodyCountAsActivity(string scenario, int expectedStarts, int expectedBodies)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var builder = WebApplication.CreateBuilder(); builder.Logging.ClearProviders();
        builder.WebHost.UseKestrel(options => options.Listen(IPAddress.Loopback, 0));
        await using var app = builder.Build(); app.UseWebSockets();
        var ended = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        app.Map("/relay", async context =>
        {
            using var server = await context.WebSockets.AcceptWebSocketAsync();
            var buffer = new byte[65536];
            try
            {
                while (true)
                {
                    var packet = await server.ReceiveAsync(buffer, timeout.Token);
                    if (packet.MessageType == WebSocketMessageType.Binary) continue;
                    if (packet.MessageType == WebSocketMessageType.Close) break;
                    using var json = JsonDocument.Parse(buffer.AsMemory(0, packet.Count));
                    var type = json.RootElement.GetProperty("type").GetString();
                    if (type is "error" or "response_end") { ended.TrySetResult(type); break; }
                    if (scenario == "head" && type == "response_start") { ended.TrySetResult(type); break; }
                }
            }
            catch (Exception) { ended.TrySetException(new InvalidOperationException("loopback_receive_failed")); }
        });
        await app.StartAsync(timeout.Token);
        using var socket = new ClientWebSocket();
        await socket.ConnectAsync(new Uri(app.Urls.Single().Replace("http://", "ws://") + "/relay"), timeout.Token);
        var service = new KaevoCloudConnectorService(null!, null!, null!, null!, null!, null!, null!, null!,
            null!, null!, null!, null!, null!, NullLogger<KaevoCloudConnectorService>.Instance);
        const BindingFlags flags = BindingFlags.Instance | BindingFlags.NonPublic;
        var httpField = typeof(KaevoCloudConnectorService).GetField("_jellyfin", flags)!;
        ((HttpClient)httpField.GetValue(service)!).Dispose();
        using var provider = new Provider(); using var http = new HttpClient(provider);
        httpField.SetValue(service, http);
        typeof(KaevoCloudConnectorService).GetField("_pairingV3Active", flags)!.SetValue(service, true);
        var seed = Enumerable.Repeat((byte)91, 32).ToArray(); const string keyId = "activity-test";
        // Reuse the retained V3 fixture encoder rather than implementing another
        // signature format. No test hook exists in the production verifier.
        var token = (string)typeof(PlaybackSecurityTests).GetMethod("V3Token", BindingFlags.Static | BindingFlags.NonPublic)!
            .Invoke(null, [seed, keyId])!;
        var configuration = new PluginConfiguration
        {
            ConnectorId = "connector-1", LocalJellyfinBaseUrl = "http://synthetic-jellyfin.invalid",
            PairingV3CloudAuthorizationIssuer = "kaevo-cloud-dev",
            PairingV3CloudAuthorizationVerificationKeysJson = JsonSerializer.Serialize(new Dictionary<string, string>
            { [keyId] = KaevoPairingV3Crypto.Base64Url(KaevoPairingV3Crypto.PublicKeyFromSeed(seed)) }),
        };
        if (scenario == "wrong-signature") token = "invalid.synthetic-token";
        var item = scenario == "wrong-item" ? new string('b', 32) : "0123456789abcdef0123456789abcdef";
        var query = new Dictionary<string, JsonElement> { ["StartTimeTicks"] = JsonSerializer.SerializeToElement(987654321) };
        if (scenario == "wrong-device") query["deviceId"] = JsonSerializer.SerializeToElement("different-device");
        var message = new RelayMessage("request", Guid.NewGuid().ToString("D"), token,
            scenario == "head" ? "HEAD" : "GET", $"/Videos/{item}/master.m3u8", query,
            scenario == "wrong-range" ? "bytes=0-1,3-4" : null);
        var activity = new Activity(); var starts = 0;
        using var request = new KaevoCloudConnectorService.RelayRequestContext(timeout.Token, () => { starts++; return activity; });
        // A transport acknowledgement, unverified body notification or context
        // creation alone cannot invoke the admitted-demand hook.
        request.AcknowledgeBody(); request.RecordVerifiedBodyProgress(); Assert.Equal(0, starts);
        using var send = new SemaphoreSlim(1, 1);
        var method = typeof(KaevoCloudConnectorService).GetMethod("HandleRelayRequestAsync", flags)!;
        var run = (Task)method.Invoke(service, [configuration, new KaevoConnectorSecrets("", "", "synthetic-api-key"), socket, send, message, request])!;
        await run.WaitAsync(timeout.Token);
        var terminal = await ended.Task.WaitAsync(timeout.Token);
        Assert.Equal(expectedStarts, starts); Assert.Equal(expectedBodies, activity.Bodies);
        Assert.Equal(expectedStarts, activity.Disposals); Assert.Equal(expectedBodies, provider.Calls);
        Assert.Equal(expectedStarts == 0 ? "error" : scenario == "head" ? "response_start" : "response_end", terminal);
        service.Dispose(); socket.Abort(); await app.StopAsync(timeout.Token);
    }
}
