using System.Text.Json;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public class FirebaseRelayDemandAdmissionTests
{
    private const string Id = "01234567-89ab-cdef-0123-456789abcdef";
    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1800000000);
    private static FirebaseControlAdmission Admission => new()
    {
        Channel = new string('a', 43), Epoch = new string('b', 32),
        CustomToken = "not-used", PushUid = "not-used", ExpiresAt = Now.AddMinutes(5),
    };
    private static Dictionary<string, object> Body => new()
    {
        ["state"] = "admitted", ["connector_id"] = "connector-test", ["demand_id"] = Id,
        ["connection_id"] = Admission.Channel, ["epoch"] = Admission.Epoch,
        ["issued_at"] = Now.ToUnixTimeSeconds(), ["expires_at"] = Now.AddSeconds(120).ToUnixTimeSeconds(),
        ["activation_allowed"] = true,
    };
    private static FirebaseRelayDemand Parse(Dictionary<string, object> body) => FirebaseRelayDemandAdmission.Parse(
        JsonSerializer.SerializeToElement(body), "connector-test", Id, Admission, Now);

    [Fact]
    public void ExactLiveReceiptRetainsOriginalDeadline()
    {
        var demand = Parse(Body);
        Assert.Equal(new FirebaseRelayDemand(Id, Now, Now.AddSeconds(120)), demand);
        Assert.Equal(demand, Parse(Body));
    }

    [Theory]
    [InlineData("state", "pending")]
    [InlineData("connector_id", "other")]
    [InlineData("demand_id", "other")]
    [InlineData("connection_id", "other")]
    [InlineData("epoch", "other")]
    [InlineData("activation_allowed", false)]
    [InlineData("activation_allowed", "true")]
    [InlineData("issued_at", true)]
    [InlineData("issued_at", "1800000000")]
    [InlineData("expires_at", true)]
    [InlineData("secret", "must-not-appear")]
    public void RejectsUnboundOrExtraFields(string key, object value)
    {
        var body = Body; body[key] = value;
        Assert.Equal("firebaseRelayDemandAdmissionInvalid", Assert.Throws<InvalidOperationException>(() => Parse(body)).Message);
    }

    [Theory]
    [InlineData(-1, 121)]
    [InlineData(1, 120)]
    [InlineData(-120, 0)]
    [InlineData(0, 121)]
    [InlineData(0, 0)]
    public void RejectsExpiredFutureOrExtendedWindow(int issuedOffset, int expiryOffset)
    {
        var body = Body;
        body["issued_at"] = Now.AddSeconds(issuedOffset).ToUnixTimeSeconds();
        body["expires_at"] = Now.AddSeconds(expiryOffset).ToUnixTimeSeconds();
        Assert.Throws<InvalidOperationException>(() => Parse(body));
    }

    [Fact]
    public void RejectsMissingDuplicateOrExpiredChannel()
    {
        var body = Body; body.Remove("epoch");
        Assert.Throws<InvalidOperationException>(() => Parse(body));
        var json = JsonSerializer.Serialize(Body);
        using var duplicate = JsonDocument.Parse(json[..^1] + ",\"state\":\"admitted\"}");
        Assert.Throws<InvalidOperationException>(() => FirebaseRelayDemandAdmission.Parse(
            duplicate.RootElement, "connector-test", Id, Admission, Now));
        Assert.Throws<InvalidOperationException>(() => FirebaseRelayDemandAdmission.Parse(
            JsonSerializer.SerializeToElement(Body), "connector-test", Id, Admission, Now.AddMinutes(5)));
    }

    [Theory]
    [InlineData("../control-ticket")]
    [InlineData("relay-demands/not-a-uuid/admit")]
    [InlineData("relay-demands/01234567-89AB-CDEF-0123-456789ABCDEF/admit")]
    [InlineData("relay-demands/01234567-89ab-cdef-0123-456789abcdef/admit?extra=1")]
    [InlineData("relay-demands/01234567-89ab-cdef-0123-456789abcdef/admit/extra")]
    public void SignedRouteAllowlistRejectsInvalidOperation(string route) => Assert.False(FirebaseRelayDemandAdmission.IsAdmissionOperation(route));

    [Fact]
    public void SignedRouteAllowlistAcceptsOnlyExactOperation() =>
        Assert.True(FirebaseRelayDemandAdmission.IsAdmissionOperation($"relay-demands/{Id}/admit"));

    private static Dictionary<string, object> RecoveryBody => new()
    {
        ["state"] = "recovered", ["connection_id"] = Admission.Channel, ["epoch"] = Admission.Epoch,
        ["activation_allowed"] = true, ["demand_ids"] = new[] { Id }, ["page_full"] = false,
        ["retry_after_seconds"] = 60,
    };
    private static FirebaseControlAdmission CurrentAdmission => new()
    {
        Channel = Admission.Channel, Epoch = Admission.Epoch, CustomToken = "not-used", PushUid = "not-used",
        ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(290),
    };
    [Fact]
    public void RecoveryReturnsOnlyHintsAndRedactsItsDescription()
    {
        var result = FirebaseRelayDemandRecovery.Parse(JsonSerializer.SerializeToElement(RecoveryBody), CurrentAdmission);
        Assert.Equal(new[] { Id }, result.DemandIds); Assert.DoesNotContain(Id, result.ToString());
        var body = RecoveryBody; body["state"] = "throttled"; body["demand_ids"] = Array.Empty<string>(); body["retry_after_seconds"] = 1;
        Assert.Empty(FirebaseRelayDemandRecovery.Parse(JsonSerializer.SerializeToElement(body), CurrentAdmission).DemandIds);
        body["demand_ids"] = new[] { Id };
        Assert.Equal(new[] { Id }, FirebaseRelayDemandRecovery.Parse(JsonSerializer.SerializeToElement(body), CurrentAdmission).DemandIds);
    }
    [Theory]
    [InlineData("state", "admitted")]
    [InlineData("connection_id", "other")]
    [InlineData("epoch", "other")]
    [InlineData("activation_allowed", false)]
    [InlineData("retry_after_seconds", 1)]
    [InlineData("retry_after_seconds", 76)]
    [InlineData("retry_after_seconds", true)]
    [InlineData("page_full", true)]
    [InlineData("private", "data")]
    public void RecoveryRejectsIncorrectShapeAndScope(string name, object value)
    {
        var body = RecoveryBody; body[name] = value;
        Assert.Equal("firebaseRelayDemandRecoveryInvalid", Assert.Throws<InvalidOperationException>(() =>
            FirebaseRelayDemandRecovery.Parse(JsonSerializer.SerializeToElement(body), CurrentAdmission)).Message);
    }
    [Theory]
    [InlineData(9, false)]
    [InlineData(2, true)]
    public void RecoveryRejectsOversizedOrDuplicateBatch(int count, bool duplicate)
    {
        var body = RecoveryBody; body["demand_ids"] = Enumerable.Range(0, count).Select(_ => duplicate ? Id : Guid.NewGuid().ToString()).ToArray();
        Assert.Throws<InvalidOperationException>(() => FirebaseRelayDemandRecovery.Parse(JsonSerializer.SerializeToElement(body), CurrentAdmission));
    }

    private static async IAsyncEnumerable<string> Hints(params string[] values)
    {
        foreach (var value in values) { await Task.Yield(); yield return value; }
    }

    [Fact]
    public async Task LostResponseRetriesSameIdOnceThenDeliversOriginalWindow()
    {
        var calls = new List<string>(); var delivered = new List<FirebaseRelayDemand>(); var commands = new List<string>();
        var evidence = new List<string>();
        await foreach (var command in FirebaseRelayDemandAdmission.FilterAsync(
            Hints(FirebaseRelayDemandAdmission.Prefix + Id, "provider-command"), (id, _) =>
            {
                calls.Add(id);
                if (calls.Count == 1) throw new InvalidOperationException("private-error-not-logged");
                return Task.FromResult(Parse(Body));
            }, (demand, _) => { delivered.Add(demand); return ValueTask.CompletedTask; }, evidence.Add, default))
            commands.Add(command);
        Assert.Equal(new[] { Id, Id }, calls);
        Assert.Equal(new[] { Parse(Body) }, delivered);
        Assert.Equal(new[] { "provider-command" }, commands);
        Assert.Equal(new[] { "demand_admission_deferred", "demand_admitted" }, evidence);
    }

    [Fact]
    public async Task DenialAndMalformedHintsNeverBecomeProviderCommands()
    {
        var calls = 0; var deliveries = 0; var commands = new List<string>();
        await foreach (var command in FirebaseRelayDemandAdmission.FilterAsync(
            Hints("relay-demand:invalid", "relay-demand:" + Id, "provider-command"), (_, _) =>
            { calls++; throw new InvalidOperationException(); }, (_, _) =>
            { deliveries++; return ValueTask.CompletedTask; }, _ => throw new Exception("evidence unavailable"), default))
            commands.Add(command);
        Assert.Equal(2, calls); Assert.Equal(0, deliveries);
        Assert.Equal(new[] { "provider-command" }, commands);
    }

    [Fact]
    public async Task CancellationDoesNotRetryOrDeliver()
    {
        using var stop = new CancellationTokenSource(); var calls = 0;
        var stream = FirebaseRelayDemandAdmission.FilterAsync(Hints("relay-demand:" + Id), (_, _) =>
        { calls++; stop.Cancel(); throw new OperationCanceledException(); }, (_, _) =>
        { throw new Exception("must not deliver"); }, _ => { }, stop.Token);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => { await foreach (var _ in stream) { } });
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task WrongReceiptIdCannotDeliverAndSinkFailureCannotReplay()
    {
        var calls = 0;
        var stream = FirebaseRelayDemandAdmission.FilterAsync(Hints("relay-demand:" + Id), (_, _) =>
        { calls++; return Task.FromResult(Parse(Body) with { Id = Guid.NewGuid().ToString() }); }, (_, _) =>
        { throw new Exception("must not deliver"); }, _ => { }, default);
        await foreach (var _ in stream) { }
        Assert.Equal(2, calls);
        calls = 0;
        stream = FirebaseRelayDemandAdmission.FilterAsync(Hints("relay-demand:" + Id), (_, _) =>
        { calls++; return Task.FromResult(Parse(Body)); }, (_, _) =>
        { throw new InvalidOperationException("sink-failed"); }, _ => { }, default);
        var error = await Assert.ThrowsAsync<InvalidOperationException>(async () => { await foreach (var _ in stream) { } });
        Assert.Equal("sink-failed", error.Message); Assert.Equal(1, calls);
    }
}
