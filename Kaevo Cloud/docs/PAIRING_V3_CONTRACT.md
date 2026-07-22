# Kaevo Pairing Protocol V3 Contract

Status: Phase A design contract; not implemented

## Canonical formats

- Protocol: `kaevo-pairing-v3`
- `pairingAttemptId`: RFC 4122 canonical, lower-case UUID string.
- `ticketId`, `pluginInstanceId`, and authorization `jti`: random opaque IDs;
  they are never accepted as proof by themselves.
- Timestamps: integer Unix milliseconds in signed request transcripts; ISO 8601
  UTC in human-facing responses where needed.
- JSON: UTF-8, object member names sorted lexicographically, no insignificant
  whitespace in signed payloads.
- Binary values: base64url without padding.

## QR payload and signature

The QR is a canonical signed JSON document. It contains the raw 256-bit ticket
secret because physical possession is the bootstrap, but it must never be
logged, stored in Cloud, or echoed by an endpoint.

```json
{
  "protocol": "kaevo-pairing-v3",
  "ticketId": "opaque-ticket-id",
  "ticketSecret": "base64url-32-byte-secret",
  "expiresAt": "2026-07-21T23:00:00Z",
  "pluginInstanceId": "opaque-plugin-instance-id",
  "pluginPublicKey": "base64url-ed25519-public-key",
  "pluginPublicKeyFingerprint": "sha256:base64url-digest",
  "jellyfinServerId": "server-id",
  "jellyfinUserId": "optional-user-id",
  "localEndpoint": "http://host:8096",
  "signature": "base64url-ed25519-signature"
}
```

The signature is Ed25519 over canonical JSON excluding `signature`, prefixed
with `KAEVO-PAIRING-V3-QR\n`. The public key permits verification of accidental
or in-transit modification; physical scan plus owner authorization remains the
trust decision for a newly encountered plugin identity. The UI must show the
server and user binding for explicit owner confirmation.

## Local challenge proof

An HMAC cannot be verified from only a one-way hash of the HMAC key. V3 uses a
ticket-secret-derived asymmetric verifier instead.

At ticket generation, the plugin derives:

```
proofSeed = HKDF-SHA-256(
  IKM = ticketSecret,
  salt = UTF8(ticketId),
  info = UTF8("kaevo-pairing-v3 ticket-proof-ed25519"),
  L = 32
)
proofPublicKey = Ed25519.PublicKey(proofSeed)
ticketSecretHash = SHA-256(ticketSecret)
```

The plugin deletes `ticketSecret` and `proofSeed`, retaining only
`ticketSecretHash` and `proofPublicKey`. iOS derives the same seed in memory
after scanning and signs this exact newline-delimited transcript:

```
KAEVO-PAIRING-V3-CHALLENGE
ticketId
challengeNonce
pairingAttemptId
pluginInstanceId
kaevo-pairing-v3
```

`POST /kaevo/v3/pairing/challenges` returns a random 32-byte nonce. The plugin
stores only its SHA-256 hash, expiry, and unused state. `complete` supplies the
nonce and Ed25519 signature; the plugin first compares nonce hash in constant
time, then verifies the signature with `proofPublicKey`, and consumes the
challenge. This avoids sending the ticket secret over local HTTP and allows the
plugin to retain no raw ticket-secret verifier.

## Cloud Pairing Authorization

Cloud returns a compact EdDSA JWS with type
`kaevo-pairing-authorization+jwt`, a Cloud signing key ID, and these claims:

```json
{
  "iss": "kaevo-cloud-dev",
  "aud": "kaevo-home-connectors-pairing-v3",
  "protocol": "kaevo-pairing-v3",
  "jti": "opaque-random-authorization-id",
  "iat": 0,
  "exp": 0,
  "pairingAttemptId": "canonical-uuid",
  "ticketId": "opaque-ticket-id",
  "pluginInstanceId": "opaque-plugin-instance-id",
  "pluginPublicKeyFingerprint": "sha256:base64url-digest",
  "jellyfinServerId": "server-id",
  "jellyfinUserId": "optional-user-id",
  "accountBinding": "opaque-derived-binding",
  "ownerSessionBinding": "opaque-derived-binding",
  "iosDeviceBinding": "opaque-derived-binding"
}
```

The response must not log or cache the authorization outside protected process
memory. Cloud persists only a hash of `jti` plus replay/idempotency state. The
authorization is valid for 60 seconds and only for the redemption audience.

## Plugin connector request signing

The plugin signs a canonical request with its long-lived Ed25519 connector key:

```
KAEVO-PAIRING-V3-REDEMPTION
POST
/v3/home-connectors/pairing/redemptions
timestampUnixMilliseconds
nonceBase64url
pairingAttemptId
SHA-256(pairingAuthorization)
pluginInstanceId
SHA-256(canonicalRequestBody)
```

Headers carry `X-Kaevo-Plugin-Key-Id`, `X-Kaevo-Plugin-Timestamp`,
`X-Kaevo-Plugin-Nonce`, and `X-Kaevo-Plugin-Signature`. The authorization is
in the request body or a dedicated header but is never logged. Cloud rejects a
timestamp outside 60 seconds, a reused nonce, unknown key, invalid signature,
or fingerprint mismatch.

## Endpoints

### `POST /v3/home-connectors/pairing/authorizations`

Authentication: existing Owner-Session-Protected DPoP authentication only.

Request (sanitized shape):

```json
{
  "protocol": "kaevo-pairing-v3",
  "pairingAttemptId": "uuid",
  "ticketId": "opaque-ticket-id",
  "pluginInstanceId": "opaque-plugin-instance-id",
  "pluginPublicKeyFingerprint": "sha256:base64url-digest",
  "jellyfinServerId": "server-id",
  "jellyfinUserId": "optional-user-id",
  "iosDeviceId": "device-binding-id"
}
```

Response `201`: `{ "protocol", "authorization", "expiresAt",
"correlationId" }`.

### `POST /kaevo/v3/pairing/challenges`

Authentication: possession of QR ticket metadata is not sufficient to enroll;
this endpoint issues only a one-use challenge.

Request: `{ "protocol", "ticketId", "pairingAttemptId" }`.

Response `201`: `{ "protocol", "ticketId", "challengeNonce", "expiresAt",
"correlationId" }`.

### `POST /kaevo/v3/pairing/complete`

Authentication: ticket-derived Ed25519 proof and Cloud Pairing Authorization.

Request: `{ "protocol", "pairingAttemptId", "ticketId", "challengeNonce",
"challengeProof", "authorization", "pluginInstanceId", "jellyfinServerId",
"jellyfinUserId" }`.

The plugin atomically reserves the ticket before redemption. Response `200` is
the structured terminal result; `202` is a non-terminal status-resolution
result. This endpoint never accepts an owner bearer token or DPoP proof.

### `POST /v3/home-connectors/pairing/redemptions`

Authentication: plugin connector-key signature plus valid Pairing Authorization.

Request contains V3 bindings, plugin public key, connector signature metadata,
and authorization. Cloud conditionally redeems the authorization and creates
or returns an idempotent connector enrollment.

### `POST /v3/home-connectors/pairing/attempts/{pairingAttemptId}`

Authentication: plugin connector-key signature over a canonical JSON body
containing the authorization JTI and binding metadata. POST is intentional: it
keeps the JTI out of a URL and binds the request body, route, timestamp, nonce,
and plugin proof in one canonical transcript. It returns only the result bound
to the same plugin instance/key and authorization binding. It is used after an
ambiguous local or Cloud response, not in the normal path.

## Versioned response and errors

Every V3 response uses:

```json
{
  "protocol": "kaevo-pairing-v3",
  "code": "pairing_reserved",
  "message": "This pairing code is currently being used.",
  "retryable": true,
  "correlationId": "canonical-uuid"
}
```

| Status | Code | Retryable |
| --- | --- | --- |
| 400 | `malformed_request` | no |
| 401 | `owner_session_required`, `reauthentication_required` | after sign-in |
| 403 | `entitlement_required`, `binding_mismatch` | no |
| 404 | `pairing_ticket_not_found` | no |
| 409 | `pairing_reserved`, `pairing_consumed`, `pairing_authorization_redeemed` | status-dependent |
| 410 | `pairing_ticket_expired`, `pairing_authorization_expired` | no |
| 422 | `invalid_challenge_proof`, `invalid_pairing_authorization` | no |
| 502 | `pairing_dependency_failure` | yes |
| 503 | `cloud_unavailable` | yes |
| 202 | `pairing_status_pending` | yes, status only |
| 500 | `unexpected_internal_error` | support-only |

Responses never contain stack traces, keys, ticket secret, nonce proof,
authorization, tokens, DPoP values, or full URLs.

## Approved cryptographic hardening (normative)

The ticket-derived signing seed is exactly:

```
HKDF-SHA-256(
  IKM = 32-byte ticketSecret,
  salt = UTF8("kaevo-pairing-v3/challenge-signing-salt"),
  info = UTF8("kaevo-pairing-v3/challenge-signing-key") || UTF8(ticketId),
  L = 32
)
```

Do not use the raw ticket secret as an Ed25519 seed. The plugin stores only
the corresponding public verifier and the ticket-secret hash. iOS derives the
private seed in memory only.

Every signed transcript begins with UTF-8 `KAEVO-PAIRING-V3\x00`. Each required
field, in the exact documented order, is encoded as UTF-8 field name, a zero
byte, a four-byte unsigned big-endian value length, and exact UTF-8 value bytes.
No serialized JSON is signed. Canonical timestamps are RFC 3339 UTC with `Z`
and seconds precision.

The challenge proof transcript order is: protocol, `challenge-response`,
ticket ID, challenge ID, nonce, pairing attempt ID, plugin instance ID, plugin
fingerprint, Jellyfin server ID, challenge issued-at, challenge expires-at,
local completion route, and SHA-256 authorization hash. The plugin signs its
challenge response with its long-lived identity key; iOS verifies signature,
key/fingerprint, instance, server, endpoint, protocol, and expiry.

The redemption transcript order is: protocol, `redemption`, method, route,
body digest, timestamp, nonce, attempt ID, authorization JTI, plugin instance
ID, plugin fingerprint, and Jellyfin server ID. Cloud rejects stale/reused
nonces, body/route/key/fingerprint/attempt/JTI mismatches, and invalid
signatures before enrollment.

## Phase B Cloud wire contract (normative)

Cloud Phase B implements and locally validates only these Cloud-owned V3
routes. They are not deployed until the reviewed dev change set is executed.
Local challenge, ticket reservation, and completion routes remain plugin-owned
and are intentionally not implemented by the Cloud Lambda in this phase.

| Route | Method | Authentication | Terminal result |
| --- | --- | --- | --- |
| `/v3/home-connectors/pairing/authorizations` | POST | Existing owner-session DPoP validation in Lambda | Signed, 60-second authorization |
| `/v3/home-connectors/pairing/redemptions` | POST | Plugin Ed25519 request signature plus signed authorization | Idempotent connector enrollment |
| `/v3/home-connectors/pairing/attempts/{pairingAttemptId}` | POST | Plugin Ed25519 request signature | Bounded ambiguity resolution |

The authorization request contains the exact V3 protocol, canonical attempt
UUID, ticket ID, plugin instance ID/fingerprint, Jellyfin server and setup-user
IDs, and the authenticated iOS device ID. The device must match the owner
session. The authorization contains no bearer token, DPoP proof, plugin private
key, or reusable Cognito credential.

For redemption, the plugin body includes the authorization, ticket ID,
canonical attempt UUID, plugin instance ID/public key/fingerprint, Jellyfin
server ID, and initial Jellyfin user ID. Its signature is over the exact
length-framed redemption transcript defined above. Its request timestamp has a
60-second skew limit and its nonce is retained for 24 hours. The user ID is
hashed into the authorization and checked again at redemption; it is enrollment
provenance, not a permanent exclusive-use binding.

Cloud records authorization JTI state, plugin nonce state, attempt idempotency,
and minimal redacted audit state in the existing app-sessions table. Connector
and server-level plugin-binding records are persisted in the existing home
connectors table. All terminal replay/idempotency records use 24-hour TTL and
the audit record uses a 30-day TTL. No new table, index, or permission is
required.

The canonical cross-language test vector is
[`PAIRING_V3_TEST_VECTORS.json`](PAIRING_V3_TEST_VECTORS.json). It fixes the
HKDF input/output, public key/fingerprint, exact field order/framing, and
Ed25519 signature. A conforming Swift, .NET, or Python implementation must
reproduce those values exactly.

Authorizations are signed, 60-second, audience-restricted V3 artifacts carrying
issuer, subject/account, protocol, attempt, ticket, plugin, server, enrollment
user provenance, iOS device, owner-session provenance, entitlement reference,
issued-at, not-before, expiry, and JTI. They contain no reusable credential.
Legacy endpoints reject V3 authorizations and V3 endpoints reject legacy
credentials.
