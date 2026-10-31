using System.Net;
using System.Text;
using System.Text.Json;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class FirebaseControlTokenExchangeTests
{
    private static readonly string Channel = new('A', 43);
    private static readonly string Epoch = new('B', 32);
    private static readonly string Uid = "connector-push-" + new string('C', 43);
    private static Dictionary<string, object> Claims() => new()
    {
        ["kaevo_purpose"] = "connector_push", ["kaevo_environment"] = "development-preview",
        ["kaevo_transport"] = "firestore-signals-v1", ["kaevo_channel"] = Channel, ["kaevo_epoch"] = Epoch,
    };
    private static string Jwt(object body) => "header." + Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(body))
        .TrimEnd('=').Replace('+', '-').Replace('/', '_') + ".signature";
    private static Dictionary<string, object> Ticket() => new()
    {
        ["state"] = "issued", ["connector_control_protocol"] = 2, ["connector_control_transport"] = "firestore-signals-v1",
        ["project_id"] = FirebaseFirestoreControlListener.DevelopmentProject, ["connection_id"] = Channel,
        ["epoch"] = Epoch, ["expires_at"] = DateTimeOffset.UtcNow.AddSeconds(120).ToUnixTimeSeconds(),
        ["custom_token"] = Jwt(new { uid = Uid, iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), claims = Claims() }), ["activation_allowed"] = false,
    };
    private static FirebaseControlAdmission Admission() => FirebaseControlAdmission.Parse(JsonSerializer.SerializeToElement(Ticket()));
    private static Dictionary<string, object> IdClaims()
    {
        var c = Claims(); var project = FirebaseFirestoreControlListener.DevelopmentProject;
        c["aud"] = project; c["iss"] = "https://securetoken.google.com/" + project; c["sub"] = Uid;
        c["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(); c["exp"] = DateTimeOffset.UtcNow.AddMinutes(30).ToUnixTimeSeconds();
        return c;
    }
    private static HttpResponseMessage Response(Dictionary<string, object>? claims = null) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(JsonSerializer.Serialize(new { idToken = Jwt(claims ?? IdClaims()),
            expiresIn = "3600", refreshToken = "must-not-be-saved" }), Encoding.UTF8, "application/json"),
    };
    private sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token) => send(request, token);
    }

    [Fact]
    public async Task ExchangeUsesFixedEndpointHeaderKeyAndMemoryOnlyToken()
    {
        var admission = Admission(); var calls = 0;
        using var http = new HttpClient(new Handler(async (request, token) =>
        {
            calls++;
            Assert.Equal("https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken", request.RequestUri!.AbsoluteUri);
            Assert.Equal("synthetic_key", request.Headers.GetValues("X-Goog-Api-Key").Single());
            using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(token));
            Assert.Equal(admission.CustomToken, body.RootElement.GetProperty("token").GetString());
            Assert.True(body.RootElement.GetProperty("returnSecureToken").GetBoolean());
            return Response();
        }));
        var result = await FirebaseControlTokenExchange.ExchangeAsync(http, "synthetic_key", admission, default);
        Assert.Equal(1, calls); Assert.DoesNotContain("must-not-be-saved", result);
        Assert.DoesNotContain(admission.CustomToken, admission.ToString());
    }

    [Theory]
    [InlineData("project_id", "other-project")]
    [InlineData("connection_id", "wrong")]
    [InlineData("epoch", "wrong")]
    [InlineData("state", "not-issued")]
    [InlineData("custom_token", "malformed")]
    [InlineData("connector_control_transport", "other")]
    public void AdmissionRejectsWrongScope(string field, string value)
    {
        var ticket = Ticket(); ticket[field] = value;
        var error = Assert.Throws<InvalidOperationException>(() => FirebaseControlAdmission.Parse(JsonSerializer.SerializeToElement(ticket)));
        Assert.Equal("firebaseControlAdmissionInvalid", error.Message); Assert.Null(error.InnerException);
    }

    [Fact]
    public void AdmissionRejectsExpiredLeaseAndDuplicateKeys()
    {
        var ticket = Ticket(); ticket["expires_at"] = 1;
        Assert.Throws<InvalidOperationException>(() => FirebaseControlAdmission.Parse(JsonSerializer.SerializeToElement(ticket)));
        using var duplicate = JsonDocument.Parse("{\"state\":\"issued\",\"state\":\"issued\"}");
        Assert.Throws<InvalidOperationException>(() => FirebaseControlAdmission.Parse(duplicate.RootElement));
    }

    [Theory]
    [InlineData("sub")]
    [InlineData("aud")]
    [InlineData("iss")]
    [InlineData("kaevo_channel")]
    [InlineData("kaevo_epoch")]
    [InlineData("kaevo_environment")]
    public async Task ExchangeRejectsWrongIdentityScope(string field)
    {
        var claims = IdClaims(); claims[field] = "other";
        using var http = new HttpClient(new Handler((_, _) => Task.FromResult(Response(claims))));
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            FirebaseControlTokenExchange.ExchangeAsync(http, "synthetic_key", Admission(), default));
        Assert.Equal("firebaseControlTokenExchangeFailed", error.Message); Assert.Null(error.InnerException);
    }

    [Theory]
    [InlineData(302)]
    [InlineData(400)]
    [InlineData(503)]
    public async Task RedirectAndProviderErrorsAreRedactedWithoutRetry(int status)
    {
        var count = 0;
        using var http = new HttpClient(new Handler((_, _) =>
        {
            count++; return Task.FromResult(new HttpResponseMessage((HttpStatusCode)status) { Content = new StringContent("private-provider-error") });
        }));
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => FirebaseControlTokenExchange.ExchangeAsync(http, "key", Admission(), default));
        Assert.Equal("firebaseControlTokenExchangeFailed", error.Message); Assert.Equal(1, count);
    }

    [Fact]
    public async Task OversizedResponseAndInvalidKeyAreRejected()
    {
        var count = 0;
        using var http = new HttpClient(new Handler((_, _) =>
        {
            count++; return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(new string('x', 16385)) });
        }));
        await Assert.ThrowsAsync<InvalidOperationException>(() => FirebaseControlTokenExchange.ExchangeAsync(http, "bad\r\nkey", Admission(), default));
        Assert.Equal(0, count);
        await Assert.ThrowsAsync<InvalidOperationException>(() => FirebaseControlTokenExchange.ExchangeAsync(http, "key", Admission(), default));
        Assert.Equal(1, count);
    }

    [Fact]
    public async Task CallerCancellationIsPreserved()
    {
        using var stop = new CancellationTokenSource();
        using var http = new HttpClient(new Handler(async (_, token) =>
        {
            stop.Cancel(); await Task.Delay(Timeout.Infinite, token); return Response();
        }));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => FirebaseControlTokenExchange.ExchangeAsync(http, "key", Admission(), stop.Token));
    }

    [Theory]
    [InlineData(-5)]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(5)]
    [InlineData(30)]
    public void TokenLifetimeUsesIssueTimeWithinExistingClockAllowance(int offset)
    {
        const long now = 1_800_000_000;
        var admission = new FirebaseControlAdmission { Channel = Channel, Epoch = Epoch,
            CustomToken = "synthetic", PushUid = Uid, IssuedAt = DateTimeOffset.FromUnixTimeSeconds(now), ExpiresAt = DateTimeOffset.FromUnixTimeSeconds(now + 120) };
        var claims = JsonSerializer.SerializeToElement(new { iat = now + offset, exp = now + offset + 3600 });
        FirebaseControlTokenExchange.CheckTokenTimes(claims, admission, now);
        Assert.Equal(now + 120, admission.ExpiresAt.ToUnixTimeSeconds());
    }

    [Theory]
    [InlineData(31, 3631)] // outside the existing future-issue allowance
    [InlineData(0, 3601)] // token lifetime exceeds one hour
    [InlineData(-3600, 0)] // expired
    [InlineData(0, 119)] // does not cover the exact channel lease
    [InlineData(0, 0)]
    [InlineData(10, 9)]
    [InlineData(-1800000000, 3600)] // invalid issue timestamp
    public void TokenTimeFailuresRemainClosed(int issueOffset, int expiryOffset)
    {
        const long now = 1_800_000_000;
        var admission = new FirebaseControlAdmission { Channel = Channel, Epoch = Epoch,
            CustomToken = "synthetic", PushUid = Uid, IssuedAt = DateTimeOffset.FromUnixTimeSeconds(now), ExpiresAt = DateTimeOffset.FromUnixTimeSeconds(now + 120) };
        var claims = JsonSerializer.SerializeToElement(new { iat = now + issueOffset, exp = now + expiryOffset });
        Assert.Throws<InvalidOperationException>(() => FirebaseControlTokenExchange.CheckTokenTimes(claims, admission, now));
    }

    [Fact]
    public async Task FreshFirebaseTokenWithSmallClockDifferenceCompletesExchange()
    {
        var claims = IdClaims();
        var issued = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 5;
        claims["iat"] = issued; claims["exp"] = issued + 3600;
        using var http = new HttpClient(new Handler((_, _) => Task.FromResult(Response(claims))));
        var evidence = new List<string>();
        var token = await FirebaseControlTokenExchange.ExchangeAsync(http, "key", Admission(), default, evidence.Add);
        Assert.NotEmpty(token); Assert.Empty(evidence);
    }

    [Fact]
    public async Task FailureEvidenceHasOnlyFixedStageAndCannotAffectOutcome()
    {
        var claims = IdClaims(); claims["kaevo_epoch"] = "private-wrong-channel";
        using var http = new HttpClient(new Handler((_, _) => Task.FromResult(Response(claims))));
        var stages = new List<string>();
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            FirebaseControlTokenExchange.ExchangeAsync(http, "private-key", Admission(), default, stage =>
            { stages.Add(stage); throw new Exception("private-diagnostic-error"); }));
        Assert.Equal(new[] { "channel_scope" }, stages);
        Assert.Equal("firebaseControlTokenExchangeFailed", error.Message);
        Assert.Null(error.InnerException);
    }

    [Theory]
    [InlineData(-5)]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(5)]
    [InlineData(30)]
    public async Task FreshFiveMinuteTicketAndTokenAcceptBoundedClockDifference(int offset)
    {
        var issued = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + offset;
        var ticket = Ticket();
        ticket["expires_at"] = issued + 300;
        ticket["custom_token"] = Jwt(new { uid = Uid, iat = issued, exp = issued + 120, claims = Claims() });
        var admission = FirebaseControlAdmission.Parse(JsonSerializer.SerializeToElement(ticket));
        var claims = IdClaims(); claims["iat"] = issued; claims["exp"] = issued + 3600;
        using var http = new HttpClient(new Handler((_, _) => Task.FromResult(Response(claims))));
        var result = await FirebaseControlTokenExchange.ExchangeAsync(http, "key", admission, default);
        Assert.NotEmpty(result);
        var localNow = DateTimeOffset.UtcNow;
        var listenerEnd = admission.ListenerExpiry(localNow);
        Assert.True(listenerEnd <= localNow.AddSeconds(300));
        Assert.True(listenerEnd <= admission.ExpiresAt);
        Assert.Equal(issued + 300, admission.ExpiresAt.ToUnixTimeSeconds());
        Assert.Equal(Channel, admission.Channel); Assert.Equal(Epoch, admission.Epoch);
        // No grace after expiry, including when a listener is reopened.
        Assert.Throws<InvalidOperationException>(() => admission.ListenerExpiry(admission.ExpiresAt));
    }

    [Theory]
    [InlineData(31, 331)]
    [InlineData(0, 301)]
    [InlineData(-301, -1)]
    [InlineData(0, 0)]
    [InlineData(10, 9)]
    [InlineData(-1800000000, 120)]
    public void TicketRejectsExcessSkewOverlongExpiredOrInvalidIssueTime(int issueOffset, int expiryOffset)
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        var admission = new FirebaseControlAdmission { Channel = Channel, Epoch = Epoch,
            CustomToken = "synthetic", PushUid = Uid, IssuedAt = now.AddSeconds(issueOffset),
            ExpiresAt = now.AddSeconds(expiryOffset) };
        Assert.Throws<InvalidOperationException>(() => admission.Check(now));
        Assert.Throws<InvalidOperationException>(() => admission.ListenerExpiry(now));
    }

    [Fact]
    public void TicketRequiresIssueTimeFromCustomTokenAndRetainsScopeChecks()
    {
        var ticket = Ticket();
        ticket["custom_token"] = Jwt(new { uid = Uid, claims = Claims() });
        Assert.Throws<InvalidOperationException>(() => FirebaseControlAdmission.Parse(JsonSerializer.SerializeToElement(ticket)));
        var claims = Claims(); claims["kaevo_channel"] = new string('Z', 43);
        ticket["custom_token"] = Jwt(new { uid = Uid, iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), claims });
        Assert.Throws<InvalidOperationException>(() => FirebaseControlAdmission.Parse(JsonSerializer.SerializeToElement(ticket)));
    }

}
