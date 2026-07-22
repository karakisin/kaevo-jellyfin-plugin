using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

internal static class KaevoPairingV3Crypto
{
    internal const string Protocol = "kaevo-pairing-v3";
    internal const string AuthorizationAudience = "kaevo-home-connectors-pairing-v3";
    private static readonly byte[] ChallengeSalt = Encoding.UTF8.GetBytes("kaevo-pairing-v3/challenge-signing-salt");
    private static readonly byte[] ChallengeInfo = Encoding.UTF8.GetBytes("kaevo-pairing-v3/challenge-signing-key");

    internal static string Base64Url(ReadOnlySpan<byte> bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    internal static byte[] Base64UrlDecode(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Any(char.IsWhiteSpace)) throw new KaevoPairingV3Exception("malformed_request");
        try { return Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/') + new string('=', (4 - value.Length % 4) % 4)); }
        catch (FormatException) { throw new KaevoPairingV3Exception("malformed_request"); }
    }

    internal static byte[] DeriveChallengeSeed(ReadOnlySpan<byte> ticketSecret, string ticketId)
    {
        if (ticketSecret.Length != 32 || string.IsNullOrWhiteSpace(ticketId)) throw new KaevoPairingV3Exception("malformed_request");
        var info = ChallengeInfo.Concat(Encoding.UTF8.GetBytes(ticketId)).ToArray();
        var prk = HMACSHA256.HashData(ChallengeSalt, ticketSecret);
        return HMACSHA256.HashData(prk, info.Concat(new byte[] { 1 }).ToArray());
    }

    internal static byte[] PublicKeyFromSeed(ReadOnlySpan<byte> seed) => new Ed25519PrivateKeyParameters(seed.ToArray(), 0).GeneratePublicKey().GetEncoded();
    internal static string Fingerprint(ReadOnlySpan<byte> publicKey) => "sha256:" + Base64Url(SHA256.HashData(publicKey));

    internal static string Sign(ReadOnlySpan<byte> privateSeed, ReadOnlySpan<byte> message)
    {
        var signer = new Ed25519Signer();
        signer.Init(true, new Ed25519PrivateKeyParameters(privateSeed.ToArray(), 0));
        signer.BlockUpdate(message.ToArray(), 0, message.Length);
        return Base64Url(signer.GenerateSignature());
    }

    internal static bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> message, string signature)
    {
        try
        {
            var signer = new Ed25519Signer();
            signer.Init(false, new Ed25519PublicKeyParameters(publicKey.ToArray(), 0));
            signer.BlockUpdate(message.ToArray(), 0, message.Length);
            return signer.VerifySignature(Base64UrlDecode(signature));
        }
        // Malformed wire data is an invalid proof, never an implementation
        // exception that can escape into a controller 500 response.
        catch (Exception) { return false; }
    }

    internal static byte[] Transcript(string operation, params (string Name, string Value)[] fields)
    {
        var supported = operation is "qr-ticket" or "challenge-response" or "redemption" or "attempt-status" or "connector-request";
        if (!supported) throw new KaevoPairingV3Exception("malformed_request");
        using var stream = new MemoryStream();
        stream.Write(Encoding.UTF8.GetBytes("KAEVO-PAIRING-V3\0"));
        AppendField(stream, "protocol", Protocol);
        AppendField(stream, "operation", operation);
        foreach (var (name, value) in fields) AppendField(stream, name, value);
        return stream.ToArray();
    }

    internal static byte[] ChallengeTranscript(KaevoPairingV3Ticket ticket, KaevoPairingV3Challenge challenge, string nonce, string authorizationHash) =>
        Transcript("challenge-response",
            ("ticketId", ticket.TicketId), ("challengeId", challenge.ChallengeId), ("challengeNonce", nonce),
            ("pairingAttemptId", challenge.PairingAttemptId), ("pluginInstanceId", ticket.PluginInstanceId),
            ("pluginPublicKeyFingerprint", ticket.PluginFingerprint), ("jellyfinServerId", ticket.JellyfinServerId),
            ("challengeIssuedAt", challenge.IssuedAtUtc.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")),
            ("challengeExpiresAt", challenge.ExpiresAtUtc.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")),
            ("localCompletionRoute", "/kaevo/v3/pairing/complete"), ("pairingAuthorizationHash", authorizationHash));

    internal static byte[] RedemptionTranscript(string method, string route, string bodyDigest, string timestamp, string nonce,
        string attemptId, string authorizationJti, string pluginInstanceId, string fingerprint, string serverId) =>
        Transcript("redemption", ("httpMethod", method.ToUpperInvariant()), ("canonicalRoute", route), ("bodyDigest", bodyDigest),
            ("timestamp", timestamp), ("nonce", nonce), ("pairingAttemptId", attemptId), ("authorizationJti", authorizationJti),
            ("pluginInstanceId", pluginInstanceId), ("pluginPublicKeyFingerprint", fingerprint), ("jellyfinServerId", serverId));

    internal static string CanonicalJsonDigest(object body)
    {
        var element = JsonSerializer.SerializeToElement(body, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        return Base64Url(SHA256.HashData(CanonicalJson(element)));
    }

    internal static string HashText(string value) => Base64Url(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    private static void AppendField(Stream stream, string name, string value)
    {
        if (string.IsNullOrWhiteSpace(name) || value.Contains('\0')) throw new KaevoPairingV3Exception("malformed_request");
        var nameBytes = Encoding.UTF8.GetBytes(name);
        var valueBytes = Encoding.UTF8.GetBytes(value);
        Span<byte> length = stackalloc byte[4];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)valueBytes.Length));
        stream.Write(nameBytes); stream.WriteByte(0); stream.Write(length); stream.Write(valueBytes);
    }

    private static byte[] CanonicalJson(JsonElement element)
    {
        using var stream = new MemoryStream();
        // Cloud canonicalizes parsed JSON with ensure_ascii=false. Use the
        // equivalent encoder so signed response bodies containing non-ASCII
        // titles produce the same digest in .NET and Python.
        using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions
        {
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        })) WriteCanonical(writer, element);
        return stream.ToArray();
    }

    private static void WriteCanonical(Utf8JsonWriter writer, JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                writer.WriteStartObject();
                foreach (var property in element.EnumerateObject().OrderBy(property => property.Name, StringComparer.Ordinal))
                { writer.WritePropertyName(property.Name); WriteCanonical(writer, property.Value); }
                writer.WriteEndObject(); break;
            case JsonValueKind.Array:
                writer.WriteStartArray(); foreach (var item in element.EnumerateArray()) WriteCanonical(writer, item); writer.WriteEndArray(); break;
            default: element.WriteTo(writer); break;
        }
    }
}

internal sealed class KaevoPairingV3Exception(string code, bool retryable = false) : Exception(code)
{
    internal string Code { get; } = code;
    internal bool Retryable { get; } = retryable;
}
