import CryptoKit
import Foundation

func hexData(_ value: String) -> Data {
    Data(stride(from: 0, to: value.count, by: 2).map { index in
        UInt8(value[value.index(value.startIndex, offsetBy: index)...value.index(value.startIndex, offsetBy: index + 1)], radix: 16)!
    })
}

func base64url(_ value: Data) -> String {
    value.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
}

func base64urlData(_ value: String) -> Data {
    let padded = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/") + String(repeating: "=", count: (4 - value.count % 4) % 4)
    return Data(base64Encoded: padded)!
}

func field(_ name: String, _ value: String) -> Data {
    var output = Data(name.utf8)
    output.append(0)
    var length = UInt32(Data(value.utf8).count).bigEndian
    withUnsafeBytes(of: &length) { output.append(contentsOf: $0) }
    output.append(Data(value.utf8))
    return output
}

let ticketSecret = hexData("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
let ticketID = "ticket-v3-vector-01"
let seed = HKDF<SHA256>.deriveKey(
    inputKeyMaterial: SymmetricKey(data: ticketSecret),
    salt: Data("kaevo-pairing-v3/challenge-signing-salt".utf8),
    info: Data("kaevo-pairing-v3/challenge-signing-key".utf8) + Data(ticketID.utf8),
    outputByteCount: 32
).withUnsafeBytes { Data($0) }
let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
let publicKey = privateKey.publicKey.rawRepresentation
let fingerprint = "sha256:" + base64url(Data(SHA256.hash(data: publicKey)))
let values = [
    ("protocol", "kaevo-pairing-v3"), ("operation", "challenge-response"),
    ("ticketId", ticketID), ("challengeId", "challenge-v3-vector-01"),
    ("challengeNonce", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
    ("pairingAttemptId", "123e4567-e89b-12d3-a456-426614174000"),
    ("pluginInstanceId", "plugin-v3-vector-01"), ("pluginPublicKeyFingerprint", fingerprint),
    ("jellyfinServerId", "server-v3-vector-01"), ("challengeIssuedAt", "2026-07-21T22:00:00Z"),
    ("challengeExpiresAt", "2026-07-21T22:00:30Z"), ("localCompletionRoute", "/kaevo/v3/pairing/complete"),
    ("pairingAuthorizationHash", "s5Wza9y2BFyqrWa6PFU24Zk861BNabbIGYj6W8tgoPtI")
]
var transcript = Data("KAEVO-PAIRING-V3\0".utf8)
for (name, value) in values { transcript.append(field(name, value)) }
let expectedSignature = base64urlData("SUjf9OsRIF5xYOANLgVNP2TidusFdf-76CLdckzwBHEYuB2HlagqFNtdtqaxbu3m7jvjMSZqbYBcAXSgBUZjCQ")
print("seedHex=\(seed.map { String(format: "%02x", $0) }.joined())")
print("publicKey=\(base64url(publicKey))")
print("fingerprint=\(fingerprint)")
print("transcriptHex=\(transcript.map { String(format: "%02x", $0) }.joined())")
print("expectedSignatureVerified=\(privateKey.publicKey.isValidSignature(expectedSignature, for: transcript))")
