using System.Text;
using System.Text.Json;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class FirebaseControlSignalReaderTests
{
    private static string Key(string id) => Convert.ToHexString(Encoding.UTF8.GetBytes(id)).ToLowerInvariant();
    private static object Signal(string id) => new { type = "remote_request_available", request_id = id, connector_control_protocol = 2 };
    private static string Event(string type, object? value) => $"event: {type}\ndata: {JsonSerializer.Serialize(value)}\n\n";
    private static async Task<List<string>> Read(string input)
    {
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(input));
        var result = new List<string>();
        await foreach (var id in FirebaseControlSignalReader.ReadAsync(stream)) result.Add(id);
        Assert.True(stream.CanRead);
        return result;
    }

    [Fact]
    public async Task SnapshotUpdatesAndDeletionYieldOnlyExactRequestHints()
    {
        var snapshot = new Dictionary<string, object?> { [Key("request_1")] = Signal("request_1"), [Key("request-2")] = Signal("request-2") };
        var input = Event("put", new { path = "/", data = snapshot })
            + Event("put", new { path = "/" + Key("request-3"), data = Signal("request-3") })
            + Event("patch", new { path = "/", data = new Dictionary<string, object?> { [Key("request-4")] = Signal("request-4"), [Key("request-2")] = null } })
            + Event("put", new { path = "/" + Key("request-1"), data = (object?)null });
        Assert.Equal(new[] { "request_1", "request-2", "request-3", "request-4" }, await Read(input));
    }

    [Fact]
    public async Task EmptySnapshotKeepaliveAndCommentsAreNotWork()
        => Assert.Empty(await Read(": heartbeat\r\n\r\n" + Event("keep-alive", null) + Event("put", new { path = "/", data = (object?)null })));

    [Fact]
    public async Task MultilineAndCrlfFramingAreAccepted()
    {
        var input = $"event: put\r\ndata: {{\r\ndata: \"path\":\"/{Key("r1")}\",\r\ndata: \"data\":{JsonSerializer.Serialize(Signal("r1"))}}}\r\n\r\n";
        Assert.Equal(new[] { "r1" }, await Read(input));
    }

    [Theory]
    [InlineData("cancel")]
    [InlineData("auth_revoked")]
    public async Task PermissionLossTerminatesWithFixedRedactedCategory(string type)
    {
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => Read(Event(type, "private diagnostic")));
        Assert.Equal("firebaseControlPermissionLost", error.Message);
    }

    [Theory]
    [InlineData("event: put\ndata: {}")]
    [InlineData("event: put\nevent: put\ndata: {}\n\n")]
    [InlineData("event: unknown\ndata: null\n\n")]
    [InlineData("event: put\ndata: {\"path\":\"/\",\"path\":\"/\",\"data\":null}\n\n")]
    [InlineData("event: put\ndata: {\"path\":\"/../secret\",\"data\":null}\n\n")]
    [InlineData("event: put\ndata: {\"path\":\"/%72\",\"data\":null}\n\n")]
    [InlineData("event: put\ndata: {\"path\":\"/FF\",\"data\":null}\n\n")]
    [InlineData("event: put\ndata: {\"path\":\"/c3a9\",\"data\":null}\n\n")]
    [InlineData("event: put\ndata: {\"path\":false,\"data\":null}\n\n")]
    [InlineData("event: keep-alive\ndata: {}\n\n")]
    public async Task MalformedEventFailsClosedWithoutPayloadInError(string input)
    {
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => Read(input));
        Assert.Equal("firebaseControlSignalInvalid", error.Message);
    }

    [Fact]
    public async Task WrongKeyBindingDoesNotEmitEarlierValidHintFromSameEvent()
    {
        var signals = new Dictionary<string, object> { [Key("r1")] = Signal("r1"), [Key("r2")] = Signal("r3") };
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(Event("put", new { path = "/", data = signals })));
        await using var enumerator = FirebaseControlSignalReader.ReadAsync(stream).GetAsyncEnumerator();
        await Assert.ThrowsAsync<InvalidOperationException>(async () => { await enumerator.MoveNextAsync(); });
    }

    [Fact]
    public async Task ExcessSignalsAndOversizeFramesAreBounded()
    {
        var signals = Enumerable.Range(0, 65).ToDictionary(i => Key("r" + i), i => Signal("r" + i));
        await Assert.ThrowsAsync<InvalidOperationException>(() => Read(Event("put", new { path = "/", data = signals })));
        await Assert.ThrowsAsync<InvalidOperationException>(() => Read(new string('a', FirebaseControlSignalReader.MaximumEventCharacters + 1)));
    }

    [Theory]
    [InlineData("r.1")]
    [InlineData("r:1")]
    [InlineData("../r1")]
    [InlineData("r1?token=private")]
    public async Task FirebaseTransportDoesNotBroadenExistingClaimIdentifiers(string id)
        => await Assert.ThrowsAsync<InvalidOperationException>(() => Read(Event("put", new { path = "/" + Key(id), data = Signal(id) })));

    [Fact]
    public async Task ProviderPayloadAndDuplicateSignalKeysAreRejected()
    {
        var payload = new { type = "remote_request_available", request_id = "r1", connector_control_protocol = 2, provider = "jellyfin" };
        await Assert.ThrowsAsync<InvalidOperationException>(() => Read(Event("put", new { path = "/" + Key("r1"), data = payload })));
        var signal = JsonSerializer.Serialize(Signal("r1"));
        await Assert.ThrowsAsync<InvalidOperationException>(() => Read($"event: put\ndata: {{\"path\":\"/\",\"data\":{{\"{Key("r1")}\":{signal},\"{Key("r1")}\":{signal}}}}}\n\n"));
    }

    [Fact]
    public async Task ArbitrarilyFragmentedNetworkReadsPreserveCompleteEvents()
    {
        using var stream = new ByteAtATimeStream(Encoding.UTF8.GetBytes(Event("put", new { path = "/" + Key("r1"), data = Signal("r1") })));
        var result = new List<string>();
        await foreach (var id in FirebaseControlSignalReader.ReadAsync(stream)) result.Add(id);
        Assert.Equal(new[] { "r1" }, result);
    }

    private sealed class ByteAtATimeStream(byte[] bytes) : MemoryStream(bytes)
    {
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            => base.ReadAsync(buffer[..Math.Min(buffer.Length, 1)], cancellationToken);
    }

    [Fact]
    public async Task CancellationAndInvalidUtf8StopReading()
    {
        using var stream = new MemoryStream(new byte[] { 0xff, 0xff });
        await using var enumerator = FirebaseControlSignalReader.ReadAsync(stream).GetAsyncEnumerator();
        await Assert.ThrowsAsync<InvalidOperationException>(async () => { await enumerator.MoveNextAsync(); });
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await using var cancelled = FirebaseControlSignalReader.ReadAsync(new MemoryStream(), cancellation.Token).GetAsyncEnumerator();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => { await cancelled.MoveNextAsync(); });
    }
}
