# Kaevo Pairing Protocol V3 — Plugin boundary

V3 is a parallel path and is disabled by default (`PairingV3Enabled=false`).
It never falls back to local-pairing V1 or V2 once a V3 ticket is issued.

## Identity and durable state

The plugin owns `pairing-v3/pairing-v3-state.json` below its data directory.
The directory is owner-only (`0700`) and the state file is owner read/write
only (`0600`). On its first enabled V3 operation the plugin creates an Ed25519
seed, a stable UUID `pluginInstanceId`, public key, SHA-256 fingerprint,
creation time, and key version. Only the owner-only state file holds the seed;
responses, connector records, logs, and artifacts expose only public identity
material. A malformed identity or state fails closed and is never regenerated.

The state model records a future rotation state and key version. Rotation is
not implemented in Phase C: it must be owner-authorized and preserve a bounded
verification period before any key is retired.

Ticket records retain a derived Ed25519 challenge-verification public key,
never the 256-bit QR ticket secret. The state gate is shared by all service
instances for the state path, and every available-to-reserved and
reserved-to-consumed mutation is written atomically. A reserved ticket remains
reserved through restart and ambiguous Cloud results; only the explicit status
recovery path may resolve it. Known-safe pre-side-effect authorization failures
release the reservation. Consumed tickets are never reopened.

## V3 flow

`POST /kaevo/v3/pairing/start` is elevated. It emits a QR URI whose signed
canonical payload carries the ticket secret only to the QR recipient.
`POST /kaevo/v3/pairing/challenges` is anonymous and binds the challenge to a
canonical pairing attempt and SHA-256 hash of the Pairing Authorization. The
extra hash is required by the approved challenge transcript; the authorization
itself is not logged or persisted.

`POST /kaevo/v3/pairing/complete` proves QR possession first, then verifies a
Cloud-signed Pairing Authorization, checks every binding, atomically reserves,
and makes one signed Cloud redemption request. The local recovery endpoint is
elevated and exists solely for an ambiguous reserved attempt. The deployed
Phase B Cloud contract defines attempt status as **POST**
`/v3/home-connectors/pairing/attempts/{pairingAttemptId}`; Phase C deliberately
uses that contract rather than changing Cloud.

The plugin verifies only a configured bounded `kid -> Ed25519 public key` set
and configured issuer. Its configuration holds no signing private key. The
production Cloud authorization signing seed must be supplied through an
approved secret-provisioning design outside SAM defaults, environment files,
fixtures, logs, and artifacts. Until that design and a public-key/issuer
rollover procedure are approved, Cloud V3 deployment remains gated.

## Connector request preparation

After a durable redemption the connector record contains only connector ID,
plugin public identity/key version, account and family bindings, Jellyfin
server/setup-user provenance, enrollment timestamp, state, attempt ID, and
protocol. It does not retain a Pairing Authorization, owner credential,
Cognito credential, DPoP proof, ticket secret, or challenge private material.

`PrepareConnectorRequestAsync` prepares canonical body-digest, timestamp,
unique nonce, connector ID, key ID, and Ed25519 proof for a future connector
management call. Phase C does not migrate heartbeat, revoke, relay-ticket, or
any legacy lifecycle traffic.

## Logging

V3 observation accepts only a canonical correlation UUID, a route template,
state transition, HTTP status, and stable outcome. Callers must truncate or
hash pairing-attempt references before emitting them. Ticket secrets,
challenge proofs, authorizations, private keys, credentials, request bodies,
and full authenticated URLs are prohibited from V3 observation.
