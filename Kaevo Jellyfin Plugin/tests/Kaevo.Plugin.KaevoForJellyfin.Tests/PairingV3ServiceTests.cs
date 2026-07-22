using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class PairingV3ServiceTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "kaevo-pairing-v3-" + Guid.NewGuid().ToString("N"));
    private static readonly byte[] CloudSeed = Convert.FromHexString("ccec87ce5b0a31ef81e39ad290c60f3e4c95e8a5b6ceb1ec132931979c23a29f");

    [Fact]
    public async Task IdentityIsStableOwnerOnlyAndMalformedPersistenceFailsClosed()
    {
        var service = Service(new FakeCloud());
        var first = await service.StartAsync("server-v3-01", "Jellyfin", "http://127.0.0.1:8096", "user-1");
        var second = await Service(new FakeCloud()).StartAsync("server-v3-02", "Jellyfin", "http://127.0.0.1:8096", "user-1");
        Assert.Equal(first.PluginInstanceId, second.PluginInstanceId);
        Assert.Equal(first.PluginPublicKey, second.PluginPublicKey);
        var path = Store().StatePath;
        if (!OperatingSystem.IsWindows())
        {
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(path));
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, File.GetUnixFileMode(Store().DirectoryPath));
        }
        var original = await File.ReadAllTextAsync(path);
        await File.WriteAllTextAsync(path, original.Replace("\"privateKeyBase64Url\":\"", "\"privateKeyBase64Url\":\"bad", StringComparison.Ordinal));
        await Assert.ThrowsAsync<InvalidOperationException>(() => Service(new FakeCloud()).StartAsync("server-v3-03", "Jellyfin", "http://127.0.0.1:8096", "user-1"));
    }

    [Fact]
    public async Task TicketPersistsOnlyVerifierAndNeverRawSecret()
    {
        var started = await Service(new FakeCloud()).StartAsync("server-v3-01", "Jellyfin", "http://127.0.0.1:8096", "user-1");
        var secret = TicketSecret(started.PairingUri);
        var state = await File.ReadAllTextAsync(Store().StatePath);
        Assert.DoesNotContain(secret, state);
        Assert.Contains("challengeVerificationPublicKey", state);
        Assert.DoesNotContain("ticketSecret", state, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(32, KaevoPairingV3Crypto.DeriveChallengeSeed(KaevoPairingV3Crypto.Base64UrlDecode(secret), started.TicketId).Length);
    }

    [Fact]
    public void FixedCloudVectorMatchesPluginHkdfPublicKeyAndChallengeProof()
    {
        var secret = Convert.FromHexString("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
        var seed = KaevoPairingV3Crypto.DeriveChallengeSeed(secret, "ticket-v3-vector-01");
        Assert.Equal("ccec87ce5b0a31ef81e39ad290c60f3e4c95e8a5b6ceb1ec132931979c23a29f", Convert.ToHexString(seed).ToLowerInvariant());
        var publicKey = KaevoPairingV3Crypto.PublicKeyFromSeed(seed);
        Assert.Equal("ZNW982EOXdEPg_In0NV5cXJ3-HcZwVrkRPRzaguYWEg", KaevoPairingV3Crypto.Base64Url(publicKey));
        Assert.Equal("sha256:x24AtE8AmJ2ELE7bTUhau6AjLsTJcv2fSVOr5MtbPCg", KaevoPairingV3Crypto.Fingerprint(publicKey));
        var ticket = new KaevoPairingV3Ticket("ticket-v3-vector-01", KaevoPairingV3Crypto.Base64Url(publicKey), DateTimeOffset.Parse("2026-07-21T22:02:00Z"),
            "plugin-v3-vector-01", KaevoPairingV3Crypto.Base64Url(publicKey), KaevoPairingV3Crypto.Fingerprint(publicKey), "server-v3-vector-01", "Jellyfin", "https://local", "user");
        var challenge = new KaevoPairingV3Challenge("challenge-v3-vector-01", ticket.TicketId, Attempt,
            "s5Wza9y2BFyqrWa6PFU24Zk861BNabbIGYj6W8tgoPtI", KaevoPairingV3Crypto.HashText("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            DateTimeOffset.Parse("2026-07-21T22:00:00Z"), DateTimeOffset.Parse("2026-07-21T22:00:30Z"));
        var transcript = KaevoPairingV3Crypto.ChallengeTranscript(ticket, challenge, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", challenge.PairingAuthorizationHash);
        Assert.Equal("SUjf9OsRIF5xYOANLgVNP2TidusFdf-76CLdckzwBHEYuB2HlagqFNtdtqaxbu3m7jvjMSZqbYBcAXSgBUZjCQ", KaevoPairingV3Crypto.Sign(seed, transcript));
        Assert.True(KaevoPairingV3Crypto.Verify(publicKey, transcript, "SUjf9OsRIF5xYOANLgVNP2TidusFdf-76CLdckzwBHEYuB2HlagqFNtdtqaxbu3m7jvjMSZqbYBcAXSgBUZjCQ"));
    }

    [Fact]
    public async Task ChallengeIsSignedAndCompletionProofConsumesOnlyAfterCloudSuccess()
    {
        var cloud = new FakeCloud { Result = new("pairing_redeemed", "connector-1") };
        var service = Service(cloud);
        var start = await service.StartAsync("server-v3-01", "Jellyfin", "http://127.0.0.1:8096", "user-1");
        var token = Authorization(start, "user-1");
        var challenge = await service.ChallengeAsync(start.TicketId, Attempt, KaevoPairingV3Crypto.HashText(token), Correlation);
        var ticket = await Ticket(start.TicketId);
        var transcript = KaevoPairingV3Crypto.ChallengeTranscript(ticket, new(challenge.ChallengeId, start.TicketId, Attempt,
            KaevoPairingV3Crypto.HashText(token), KaevoPairingV3Crypto.HashText(challenge.ChallengeNonce), challenge.IssuedAtUtc, challenge.ExpiresAtUtc), challenge.ChallengeNonce, KaevoPairingV3Crypto.HashText(token));
        Assert.True(KaevoPairingV3Crypto.Verify(KaevoPairingV3Crypto.Base64UrlDecode(start.PluginPublicKey), transcript, challenge.Signature));
        var proof = KaevoPairingV3Crypto.Sign(KaevoPairingV3Crypto.DeriveChallengeSeed(KaevoPairingV3Crypto.Base64UrlDecode(TicketSecret(start.PairingUri)), start.TicketId), transcript);
        var result = await service.CompleteAsync(new Uri("https://cloud.example"), new(KaevoPairingV3Crypto.Protocol, start.TicketId, Attempt, challenge.ChallengeId, challenge.ChallengeNonce, proof, token, "user-1", Correlation));
        Assert.Equal("pairing_redeemed", result.Code);
        var state = await Store().ReadAsync(value => value);
        Assert.Equal("consumed", state.Tickets[start.TicketId].State);
        Assert.Equal("connector-1", state.Connector!.ConnectorId);
        Assert.DoesNotContain(token, await File.ReadAllTextAsync(Store().StatePath));
    }

    [Fact]
    public async Task LocalStatusReportsOnlyPairedStateWithoutConnectorOrBindingMaterial()
    {
        var service = Service(new FakeCloud());
        var before = await service.GetLocalStatusAsync();
        Assert.Equal("not_paired", before.State);
        Assert.Equal(KaevoPairingV3Crypto.Protocol, before.Protocol);
        Assert.False(before.RequiresReauthentication);

        await Store().MutateAsync(state =>
        {
            state.Connector = new KaevoPairingV3Connector(
                "connector-not-exposed", "plugin-instance-not-exposed", "public-key-not-exposed", "fingerprint-not-exposed", 1,
                "account-not-exposed", "family-not-exposed", "server-not-exposed", "user-not-exposed", DateTimeOffset.UtcNow,
                "active", Attempt, KaevoPairingV3Crypto.Protocol);
            return 0;
        });

        var paired = await service.GetLocalStatusAsync();
        Assert.Equal("paired", paired.State);
        Assert.Equal(KaevoPairingV3Crypto.Protocol, paired.Protocol);
        Assert.False(paired.RequiresReauthentication);
        var json = JsonSerializer.Serialize(paired);
        Assert.DoesNotContain("connector-not-exposed", json);
        Assert.DoesNotContain("server-not-exposed", json);
        Assert.DoesNotContain("account-not-exposed", json);
    }

    [Fact]
    public async Task WrongCloudKeyAudienceFingerprintServerAttemptAndUserAreRejected()
    {
        var start = await Service(new FakeCloud()).StartAsync("server-v3-01", "Jellyfin", "http://127.0.0.1:8096", "user-1");
        var wrongKey = Service(new FakeCloud(), "{\"other\":\"invalid\"}");
        await Assert.ThrowsAsync<KaevoPairingV3Exception>(() => wrongKey.CompleteAsync(new Uri("https://cloud.example"), InvalidCompletion(start, Authorization(start, "user-1"))));
        foreach (var token in new[] {
            Authorization(start, "user-1", audience: "wrong"), Authorization(start, "user-1", fingerprint: "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            Authorization(start, "user-1", server: "server-v3-other"), Authorization(start, "user-1", attempt: "123e4567-e89b-12d3-a456-426614174001"), Authorization(start, "user-2") })
        {
            await Assert.ThrowsAsync<KaevoPairingV3Exception>(() => Service(new FakeCloud()).CompleteAsync(new Uri("https://cloud.example"), InvalidCompletion(start, token)));
        }
    }

    [Fact]
    public async Task ConcurrentCompletionHasOneReservationWinnerAndAmbiguousOutcomeSurvivesRestart()
    {
        var cloud = new BlockingCloud(); var service = Service(cloud);
        var start = await service.StartAsync("server-v3-01", "Jellyfin", "http://127.0.0.1:8096", "user-1");
        var token = Authorization(start, "user-1");
        var challenge = await service.ChallengeAsync(start.TicketId, Attempt, KaevoPairingV3Crypto.HashText(token), Correlation);
        var completion = ValidCompletion(start, challenge, token);
        var first = service.CompleteAsync(new Uri("https://cloud.example"), completion);
        await cloud.Entered.Task;
        // A recreated service shares the durable-path gate rather than relying
        // on a request-local lock.
        var second = await Assert.ThrowsAsync<KaevoPairingV3Exception>(() => Service(cloud).CompleteAsync(new Uri("https://cloud.example"), completion));
        Assert.Equal("pairing_reserved", second.Code);
        cloud.Release.TrySetResult(new("ambiguous_enrollment", Retryable: true));
        Assert.Equal("ambiguous_enrollment", (await first).Code);
        var restarted = await Store().ReadAsync(value => value.Tickets[start.TicketId]);
        Assert.Equal("reserved", restarted.State);
        Assert.Equal(Attempt, restarted.PairingAttemptId);
    }

    [Fact]
    public async Task SafeAuthFailureReleasesReservationWithoutConsumingTicket()
    {
        var cloud = new FakeCloud { Result = new("invalid_pairing_authorization") };
        var service = Service(cloud);
        var start = await service.StartAsync("server-v3-01", "Jellyfin", "http://127.0.0.1:8096", "user-1");
        var token = Authorization(start, "user-1");
        var challenge = await service.ChallengeAsync(start.TicketId, Attempt, KaevoPairingV3Crypto.HashText(token), Correlation);
        Assert.Equal("invalid_pairing_authorization", (await service.CompleteAsync(new Uri("https://cloud.example"), ValidCompletion(start, challenge, token))).Code);
        Assert.Equal("available", (await Ticket(start.TicketId)).State);
    }

    [Fact]
    public async Task DisabledV3AndExpiredTicketFailWithStructuredErrors()
    {
        var disabled = new KaevoPairingV3Service(Store(), new FakeCloud(), () => false, () => "{}", () => "kaevo-cloud-dev");
        var exception = await Assert.ThrowsAsync<KaevoPairingV3Exception>(() => disabled.StartAsync("server", "Jellyfin", "https://local", "user"));
        Assert.Equal("pairing_v3_disabled", exception.Code);
        var start = await Service(new FakeCloud()).StartAsync("server-v3-01", "Jellyfin", "https://local", "user-1");
        await Store().MutateAsync(state => { state.Tickets[start.TicketId] = state.Tickets[start.TicketId] with { ExpiresAtUtc = DateTimeOffset.UtcNow.AddSeconds(-1) }; return 0; });
        var expired = await Assert.ThrowsAsync<KaevoPairingV3Exception>(() => Service(new FakeCloud()).ChallengeAsync(start.TicketId, Attempt, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Correlation));
        Assert.Equal("pairing_ticket_expired", expired.Code);
    }

    [Fact]
    public async Task ExpiredChallengeAndMalformedProofAreRejectedBeforeAuthorizationParsing()
    {
        var start = await Service(new FakeCloud()).StartAsync("server-v3-01", "Jellyfin", "https://local", "user-1");
        var token = Authorization(start, "user-1");
        var challenge = await Service(new FakeCloud()).ChallengeAsync(start.TicketId, Attempt, KaevoPairingV3Crypto.HashText(token), Correlation);
        await Store().MutateAsync(state => { state.Challenges[challenge.ChallengeId] = state.Challenges[challenge.ChallengeId] with { ExpiresAtUtc = DateTimeOffset.UtcNow.AddSeconds(-1) }; return 0; });
        var expired = await Assert.ThrowsAsync<KaevoPairingV3Exception>(() => Service(new FakeCloud()).CompleteAsync(new Uri("https://cloud.example"), ValidCompletion(start, challenge, token)));
        Assert.Equal("challenge_expired", expired.Code);
        await Store().MutateAsync(state => { state.Challenges[challenge.ChallengeId] = state.Challenges[challenge.ChallengeId] with { ExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(1) }; return 0; });
        var invalid = ValidCompletion(start, challenge, "not.a.valid.authorization") with { ChallengeResponseSignature = "not-a-signature" };
        var proof = await Assert.ThrowsAsync<KaevoPairingV3Exception>(() => Service(new FakeCloud()).CompleteAsync(new Uri("https://cloud.example"), invalid));
        Assert.Equal("invalid_challenge_proof", proof.Code);
    }

    [Fact]
    public async Task ValidProofRejectsWrongCloudKeyAudienceIssuerAndBindings()
    {
        var keyStart = await Service(new FakeCloud()).StartAsync("server-v3-01", "Jellyfin", "https://local", "user-1");
        var keyToken = Authorization(keyStart, "user-1");
        var keyChallenge = await Service(new FakeCloud()).ChallengeAsync(keyStart.TicketId, Attempt, KaevoPairingV3Crypto.HashText(keyToken), Correlation);
        var wrongKey = Service(new FakeCloud(), "{\"cloud-test\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}");
        var wrongKeyError = await Assert.ThrowsAsync<KaevoPairingV3Exception>(() => wrongKey.CompleteAsync(new Uri("https://cloud.example"), ValidCompletion(keyStart, keyChallenge, keyToken)));
        Assert.Equal("invalid_pairing_authorization", wrongKeyError.Code);
        foreach (var (name, mutation) in new (string, Func<KaevoPairingV3Start, string>)[]
        {
            ("audience", start => Authorization(start, "user-1", audience: "wrong")),
            ("issuer", start => Authorization(start, "user-1", issuer: "kaevo-cloud-other")),
            ("fingerprint", start => Authorization(start, "user-1", fingerprint: "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")),
            ("server", start => Authorization(start, "user-1", server: "server-v3-other")),
            ("attempt", start => Authorization(start, "user-1", attempt: "123e4567-e89b-12d3-a456-426614174009")),
            ("user", start => Authorization(start, "user-2")),
        })
        {
            var start = await Service(new FakeCloud()).StartAsync("server-v3-01", "Jellyfin", "https://local", "user-1");
            var token = mutation(start);
            var challenge = await Service(new FakeCloud()).ChallengeAsync(start.TicketId, Attempt, KaevoPairingV3Crypto.HashText(token), Correlation);
            var error = await Assert.ThrowsAsync<KaevoPairingV3Exception>(() => Service(new FakeCloud()).CompleteAsync(new Uri("https://cloud.example"), ValidCompletion(start, challenge, token)));
            Assert.True(error.Code is "invalid_pairing_authorization" or "binding_mismatch", name + ":" + error.Code);
        }
    }

    [Fact]
    public async Task RedemptionSignatureBindsTheCanonicalBodyAndPluginKeyVersion()
    {
        var cloud = new CapturingCloud(new("pairing_redeemed", "connector-1"));
        var service = Service(cloud);
        var start = await service.StartAsync("server-v3-01", "Jellyfin", "https://local", "user-1");
        var token = Authorization(start, "user-1");
        var challenge = await service.ChallengeAsync(start.TicketId, Attempt, KaevoPairingV3Crypto.HashText(token), Correlation);
        await service.CompleteAsync(new Uri("https://cloud.example"), ValidCompletion(start, challenge, token));
        var request = Assert.IsType<KaevoPairingV3RedemptionRequest>(cloud.Redemption);
        Assert.Equal("1", request.PluginKeyId);
        var body = new { protocol = KaevoPairingV3Crypto.Protocol, authorization = request.Authorization, ticketId = request.TicketId, pairingAttemptId = request.PairingAttemptId,
            pluginInstanceId = request.PluginInstanceId, pluginPublicKey = request.PluginPublicKey, pluginPublicKeyFingerprint = request.PluginPublicKeyFingerprint,
            jellyfinServerId = request.JellyfinServerId, jellyfinUserId = request.JellyfinUserId, pluginKeyId = request.PluginKeyId };
        var transcript = KaevoPairingV3Crypto.RedemptionTranscript("POST", "/v3/home-connectors/pairing/redemptions", KaevoPairingV3Crypto.CanonicalJsonDigest(body), request.Timestamp,
            request.Nonce, request.PairingAttemptId, request.AuthorizationJti, request.PluginInstanceId, request.PluginPublicKeyFingerprint, request.JellyfinServerId);
        Assert.True(KaevoPairingV3Crypto.Verify(KaevoPairingV3Crypto.Base64UrlDecode(start.PluginPublicKey), transcript, request.Signature));
        Assert.NotEqual(KaevoPairingV3Crypto.CanonicalJsonDigest(body), KaevoPairingV3Crypto.CanonicalJsonDigest(new { body.protocol, body.authorization, body.ticketId, body.pairingAttemptId,
            body.pluginInstanceId, body.pluginPublicKey, body.pluginPublicKeyFingerprint, body.jellyfinServerId, body.jellyfinUserId, pluginKeyId = "2" }));
    }

    [Fact]
    public async Task LostResponseRecoversThroughStatusAndConsumesDurably()
    {
        var cloud = new CapturingCloud(new("ambiguous_enrollment", Retryable: true)) { StatusResult = new("pairing_redeemed", "connector-1", Idempotent: true) };
        var service = Service(cloud);
        var start = await service.StartAsync("server-v3-01", "Jellyfin", "https://local", "user-1");
        var token = Authorization(start, "user-1");
        var challenge = await service.ChallengeAsync(start.TicketId, Attempt, KaevoPairingV3Crypto.HashText(token), Correlation);
        Assert.Equal("ambiguous_enrollment", (await service.CompleteAsync(new Uri("https://cloud.example"), ValidCompletion(start, challenge, token))).Code);
        var recovered = await Service(cloud).RecoverAsync(new Uri("https://cloud.example"), start.TicketId, Correlation);
        Assert.Equal("pairing_redeemed", recovered.Code);
        Assert.True(recovered.Idempotent);
        Assert.Equal("consumed", (await Ticket(start.TicketId)).State);
        Assert.NotNull(cloud.Status);
    }

    [Fact]
    public async Task PostPairingRequestPreparationUsesStableIdentityWithoutPersistingSecretsInOutput()
    {
        var service = Service(new FakeCloud());
        var start = await service.StartAsync("server-v3-01", "Jellyfin", "https://local", "user-1");
        var token = Authorization(start, "user-1");
        var challenge = await service.ChallengeAsync(start.TicketId, Attempt, KaevoPairingV3Crypto.HashText(token), Correlation);
        await service.CompleteAsync(new Uri("https://cloud.example"), ValidCompletion(start, challenge, token));
        var request = await service.PrepareConnectorRequestAsync("POST", "/v3/future", new { value = "safe" });
        Assert.Equal("connector-1", request.ConnectorId);
        Assert.Equal("1", request.PluginKeyId);
        Assert.False(string.IsNullOrWhiteSpace(request.Signature));
        Assert.DoesNotContain(token, JsonSerializer.Serialize(request));
    }

    [Fact]
    public async Task ObservationsAreAllowlistedAndDoNotContainPairingSecrets()
    {
        var observations = new List<string>();
        var service = new KaevoPairingV3Service(Store(), new FakeCloud(), () => true,
            () => JsonSerializer.Serialize(new Dictionary<string, string> { ["cloud-test"] = KaevoPairingV3Crypto.Base64Url(KaevoPairingV3Crypto.PublicKeyFromSeed(CloudSeed)) }),
            () => "kaevo-cloud-dev", (correlation, attempt, route, transition, status, outcome) => observations.Add($"{correlation}|{attempt}|{route}|{transition}|{status}|{outcome}"));
        var start = await service.StartAsync("server-v3-01", "Jellyfin", "https://local", "user-1");
        var token = Authorization(start, "user-1");
        var challenge = await service.ChallengeAsync(start.TicketId, Attempt, KaevoPairingV3Crypto.HashText(token), Correlation);
        await service.CompleteAsync(new Uri("https://cloud.example"), ValidCompletion(start, challenge, token));
        var emitted = string.Join("\n", observations);
        Assert.Contains(Correlation, emitted);
        Assert.Contains(Attempt[..8], emitted);
        Assert.DoesNotContain(Attempt, emitted);
        Assert.DoesNotContain(token, emitted);
        Assert.DoesNotContain(TicketSecret(start.PairingUri), emitted);
        Assert.DoesNotContain(challenge.Signature, emitted);
    }

    private KaevoPairingV3Store Store() => new(_directory);
    private KaevoPairingV3Service Service(IKaevoPairingV3CloudClient cloud, string? keys = null) => new(Store(), cloud, () => true,
        () => keys ?? JsonSerializer.Serialize(new Dictionary<string, string> { ["cloud-test"] = KaevoPairingV3Crypto.Base64Url(KaevoPairingV3Crypto.PublicKeyFromSeed(CloudSeed)) }),
        () => "kaevo-cloud-dev");
    private Task<KaevoPairingV3Ticket> Ticket(string id) => Store().ReadAsync(state => state.Tickets[id]);

    private static string Authorization(KaevoPairingV3Start start, string user, string? audience = null, string? fingerprint = null, string? server = null, string? attempt = null, string? issuer = null)
    {
        var header = KaevoPairingV3Crypto.Base64Url(JsonSerializer.SerializeToUtf8Bytes(new { alg = "EdDSA", kid = "cloud-test", typ = "kaevo-pairing-authorization+jwt" }));
        var claims = new Dictionary<string, object> {
            ["iss"] = issuer ?? "kaevo-cloud-dev", ["sub"] = "subject", ["jti"] = "123e4567-e89b-12d3-a456-426614174002", ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), ["nbf"] = DateTimeOffset.UtcNow.AddSeconds(-1).ToUnixTimeSeconds(),
            ["pairingAttemptId"] = attempt ?? Attempt, ["ticketId"] = start.TicketId, ["pluginInstanceId"] = start.PluginInstanceId,
            ["pluginPublicKeyFingerprint"] = fingerprint ?? start.PluginFingerprint, ["jellyfinServerId"] = server ?? start.JellyfinServerId,
            ["jellyfinUserProvenance"] = KaevoPairingV3Crypto.HashText(user), ["accountBinding"] = "account", ["familyBinding"] = "family",
            ["ownerSessionProvenance"] = "owner", ["iosDeviceBinding"] = "device", ["entitlement"] = "cloud_enabled",
            ["exp"] = DateTimeOffset.UtcNow.AddMinutes(1).ToUnixTimeSeconds(), ["aud"] = audience ?? KaevoPairingV3Crypto.AuthorizationAudience, ["protocol"] = KaevoPairingV3Crypto.Protocol };
        var payload = KaevoPairingV3Crypto.Base64Url(JsonSerializer.SerializeToUtf8Bytes(claims));
        return header + "." + payload + "." + KaevoPairingV3Crypto.Sign(CloudSeed, Encoding.ASCII.GetBytes(header + "." + payload));
    }

    private static KaevoPairingV3Completion ValidCompletion(KaevoPairingV3Start start, KaevoPairingV3ChallengeResponse challenge, string token)
    {
        var ticketSecret = KaevoPairingV3Crypto.Base64UrlDecode(TicketSecret(start.PairingUri));
        var ticket = new KaevoPairingV3Ticket(start.TicketId, KaevoPairingV3Crypto.Base64Url(KaevoPairingV3Crypto.PublicKeyFromSeed(KaevoPairingV3Crypto.DeriveChallengeSeed(ticketSecret, start.TicketId))), start.ExpiresAtUtc, start.PluginInstanceId, start.PluginPublicKey, start.PluginFingerprint, start.JellyfinServerId, start.JellyfinServerName, start.LocalEndpoint, "user-1");
        var storedChallenge = new KaevoPairingV3Challenge(challenge.ChallengeId, start.TicketId, Attempt, KaevoPairingV3Crypto.HashText(token), KaevoPairingV3Crypto.HashText(challenge.ChallengeNonce), challenge.IssuedAtUtc, challenge.ExpiresAtUtc);
        var proof = KaevoPairingV3Crypto.Sign(KaevoPairingV3Crypto.DeriveChallengeSeed(ticketSecret, start.TicketId), KaevoPairingV3Crypto.ChallengeTranscript(ticket, storedChallenge, challenge.ChallengeNonce, KaevoPairingV3Crypto.HashText(token)));
        return new(KaevoPairingV3Crypto.Protocol, start.TicketId, Attempt, challenge.ChallengeId, challenge.ChallengeNonce, proof, token, "user-1", Correlation);
    }

    private static KaevoPairingV3Completion InvalidCompletion(KaevoPairingV3Start start, string token) => new(KaevoPairingV3Crypto.Protocol, start.TicketId, Attempt, "missing", "nonce", "signature", token, "user-1", Correlation);

    private static string TicketSecret(string uri)
    {
        var payload = Uri.UnescapeDataString(uri.Split("payload=", StringSplitOptions.None)[1].Split("&signature=", StringSplitOptions.None)[0]);
        var bytes = KaevoPairingV3Crypto.Base64UrlDecode(payload); var offset = Encoding.UTF8.GetByteCount("KAEVO-PAIRING-V3\0");
        var fields = new Dictionary<string, string>();
        while (offset < bytes.Length)
        {
            var end = Array.IndexOf(bytes, (byte)0, offset); var name = Encoding.UTF8.GetString(bytes, offset, end - offset); offset = end + 1;
            var length = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(offset, 4)); offset += 4;
            fields[name] = Encoding.UTF8.GetString(bytes, offset, checked((int)length)); offset += checked((int)length);
        }
        return fields["ticketSecret"];
    }

    public void Dispose() { if (Directory.Exists(_directory)) Directory.Delete(_directory, true); }

    private const string Attempt = "123e4567-e89b-12d3-a456-426614174000";
    private const string Correlation = "123e4567-e89b-12d3-a456-426614174001";

    private sealed class FakeCloud : IKaevoPairingV3CloudClient
    {
        public KaevoPairingV3CloudResult Result { get; init; } = new("pairing_redeemed", "connector-1");
        public Task<KaevoPairingV3CloudResult> RedeemAsync(Uri _, KaevoPairingV3RedemptionRequest __, CancellationToken ___) => Task.FromResult(Result);
        public Task<KaevoPairingV3CloudResult> StatusAsync(Uri _, KaevoPairingV3StatusRequest __, CancellationToken ___) => Task.FromResult(Result);
    }

    private sealed class BlockingCloud : IKaevoPairingV3CloudClient
    {
        public TaskCompletionSource<bool> Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource<KaevoPairingV3CloudResult> Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Task<KaevoPairingV3CloudResult> RedeemAsync(Uri _, KaevoPairingV3RedemptionRequest __, CancellationToken ___) { Entered.TrySetResult(true); return Release.Task; }
        public Task<KaevoPairingV3CloudResult> StatusAsync(Uri _, KaevoPairingV3StatusRequest __, CancellationToken ___) => Task.FromResult(new KaevoPairingV3CloudResult("pairing_status_pending", Retryable: true));
    }

    private sealed class CapturingCloud(KaevoPairingV3CloudResult redemption) : IKaevoPairingV3CloudClient
    {
        public KaevoPairingV3RedemptionRequest? Redemption { get; private set; }
        public KaevoPairingV3StatusRequest? Status { get; private set; }
        public KaevoPairingV3CloudResult StatusResult { get; init; } = new("pairing_status_pending", Retryable: true);
        public Task<KaevoPairingV3CloudResult> RedeemAsync(Uri _, KaevoPairingV3RedemptionRequest request, CancellationToken ___) { Redemption = request; return Task.FromResult(redemption); }
        public Task<KaevoPairingV3CloudResult> StatusAsync(Uri _, KaevoPairingV3StatusRequest request, CancellationToken ___) { Status = request; return Task.FromResult(StatusResult); }
    }
}
