# KSEC-012A - Home Connector Lifecycle Security

Date: 2026-07-18
Severity: High - fail-closed launch blocker
Branch: `security/connector-lifecycle-state-machine-2026-07-18`

## Root cause

Initial P-256 pairing existed without one authoritative lifecycle for immutable
server binding, monotonic credential versions, rotation, recovery, revocation,
and atomic audit evidence. Pairing could activate before its audit write, and
revocation emitted no required security audit.

## Authoritative state machine

```text
pending_pairing -> active
active -> rotation_pending -> active(version + 1)
active -> recovery_pending -> active(version + 1)
active|rotation_pending|recovery_pending -> revoked
pending intent -> canceled (prior accepted key remains authoritative)
```

The existing Home connector table stores both connector records and unique
`server_binding` reservation records. The existing app-session table stores
short-lived, single-use lifecycle intents. No table or index replacement is
required.

Each server generates a random `srv_` identifier locally and persists it with
its Cloud environment. Cloud binds the environment, authoritative account and
household, server ID, and connector ID. A conditional server-binding write
prevents a second connector from claiming the same server. Clients never supply
authoritative account, household, role, or version values.

## Credential versions and authentication

Initial activation changes version 0 to version 1. Rotation and recovery may
change only `current + 1`; `max_issued_credential_version` must equal the current
version before and during the transaction. Connector requests must present the
current version, current P-256 thumbprint, valid DPoP method/URL/time/JTI
bindings, active environment and server binding, and a non-revoked state.

Rotation proves possession of both current and proposed keys. Recovery proves
possession of a separate locally persisted recovery P-256 key plus the proposed
new key and requires recent authoritative owner approval. Owner credentials
alone and local presence alone are insufficient. Revoked connectors cannot use
ordinary rotation or recovery, so compromised versions remain permanently
unusable.

## Local key safety

The Home Server stores its immutable server ID, current connector/version, a
versioned connector private key, and a separate recovery private key locally
under a mode-0700 directory with mode-0600 files. State updates use
same-directory temporary files, `fsync`, and atomic replacement. A proposed key
remains pending until Cloud activation succeeds; failure preserves the current
key. Successful activation replaces the key and best-effort overwrites/removes
the superseded local key. Cloud receives public JWKs, thumbprints, DPoP proofs,
and non-secret lifecycle metadata only.

## Atomic audit evidence

Pairing intent creation, pairing activation, rotation intent/activation,
recovery intent/activation, cancellation, and revocation commit connector,
binding, intent, and KSEC-010B privacy-safe audit records in one DynamoDB
transaction. Activation cannot succeed without durable audit evidence.
Revocation uses a non-correlatable fallback audit record when the audit key is
unavailable so containment remains available without retaining raw identity.

## Migration and operational limits

Existing legacy connectors have no server binding or monotonic version and are
not silently upgraded. Non-development environments return
`lifecycle_upgrade_required`; a recently authenticated owner must perform a new
lifecycle enrollment. No production migration is authorized by this candidate.

KSEC-012A remains open until the tagged candidate passes isolated AWS staging,
including pairing, rotation, old-key rejection, recovery, revocation, atomic
audit inspection, cross-tenant denial, restart recovery, and complete cleanup.
