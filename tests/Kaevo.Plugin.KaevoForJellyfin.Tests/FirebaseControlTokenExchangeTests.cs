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
        ["custom_token"] = Jwt(new { uid = Uid, claims = Claims() }), ["activation_allowed"] = false,
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
}
