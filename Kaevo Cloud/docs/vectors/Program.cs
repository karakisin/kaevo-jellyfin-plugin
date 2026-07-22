using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

static byte[] HkdfSha256(byte[] ikm, byte[] salt, byte[] info)
{
    var prk = HMACSHA256.HashData(salt, ikm);
    var input = info.Concat(new byte[] { 1 }).ToArray();
    return HMACSHA256.HashData(prk, input);
}

static void AppendField(List<byte> output, string name, string value)
{
    var nameBytes = Encoding.UTF8.GetBytes(name);
    var valueBytes = Encoding.UTF8.GetBytes(value);
    output.AddRange(nameBytes);
    output.Add(0);
    Span<byte> length = stackalloc byte[4];
    BinaryPrimitives.WriteUInt32BigEndian(length, (uint)valueBytes.Length);
    output.AddRange(length.ToArray());
    output.AddRange(valueBytes);
}

var ticketSecret = Convert.FromHexString("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
var ticketId = "ticket-v3-vector-01";
var seed = HkdfSha256(ticketSecret, Encoding.UTF8.GetBytes("kaevo-pairing-v3/challenge-signing-salt"), Encoding.UTF8.GetBytes("kaevo-pairing-v3/challenge-signing-key" + ticketId));
var transcript = new List<byte>(Encoding.UTF8.GetBytes("KAEVO-PAIRING-V3\0"));
foreach (var (name, value) in new (string, string)[] {
    ("protocol", "kaevo-pairing-v3"), ("operation", "challenge-response"),
    ("ticketId", ticketId), ("challengeId", "challenge-v3-vector-01"),
    ("challengeNonce", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
    ("pairingAttemptId", "123e4567-e89b-12d3-a456-426614174000"),
    ("pluginInstanceId", "plugin-v3-vector-01"), ("pluginPublicKeyFingerprint", "sha256:x24AtE8AmJ2ELE7bTUhau6AjLsTJcv2fSVOr5MtbPCg"),
    ("jellyfinServerId", "server-v3-vector-01"), ("challengeIssuedAt", "2026-07-21T22:00:00Z"),
    ("challengeExpiresAt", "2026-07-21T22:00:30Z"), ("localCompletionRoute", "/kaevo/v3/pairing/complete"),
    ("pairingAuthorizationHash", "s5Wza9y2BFyqrWa6PFU24Zk861BNabbIGYj6W8tgoPtI")
}) AppendField(transcript, name, value);

Console.WriteLine($"seedHex={Convert.ToHexString(seed).ToLowerInvariant()}");
Console.WriteLine($"transcriptHex={Convert.ToHexString(transcript.ToArray()).ToLowerInvariant()}");
