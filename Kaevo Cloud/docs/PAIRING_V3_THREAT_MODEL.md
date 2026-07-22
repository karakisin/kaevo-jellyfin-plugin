# Kaevo Pairing Protocol V3 Threat Model and Test Plan

Status: Phase A design review

## Security invariants

1. iOS owner credentials and owner DPoP key never enter the plugin process.
2. Plugin connector private keys never leave the Jellyfin server.
3. QR ticket secrets never enter logs, Cloud storage, error responses, or
   source control.
4. A ticket is consumed only after Cloud enrollment and local persistence are
   both durable.
5. One authorization and one ticket cannot create duplicate connectors.
6. A correlation UUID is not authorization evidence.
7. v1/v2 cannot be silently selected as a fallback for a V3 payload.

## Threats and mitigations

| Threat | Mitigation | Residual risk |
| --- | --- | --- |
| QR theft | 120-second ticket, owner DPoP authorization, display/confirm server binding, one-use ticket | A thief with an unlocked authenticated iPhone can act during the window |
| LAN interception | Ticket-derived asymmetric challenge proof; nonce is one-use; owner token never goes to plugin | A compromised LAN endpoint can deny service |
| Ticket replay | SHA-256 secret hash, single-use challenge, atomic ticket reservation, consumed state | None after durable consumption |
| Authorization theft | 60-second audience-bound JWS, plugin key/fingerprint binding, one-time Cloud state | Attacker who controls the intended plugin may use it before expiry |
| Plugin impersonation | Random stable instance ID, Ed25519 connector key, signed redemption, fingerprint-bound authorization | Compromised plugin host is a trusted-endpoint compromise |
| App impersonation | Owner Session Protected DPoP and device-bound session validation | Compromised unlocked iPhone remains an endpoint risk |
| Cloud replay | Authorization JTI conditional state, request nonce replay guard, attempt idempotency | Bounded storage required for replay guard retention |
| Concurrent scans | Atomic `Available -> Reserved`; distinct attempt receives conflict | Owner experience requires clear `pairing_reserved` UI |
| Server/user/device/account mismatch | Authorization binds all required values; Cloud and plugin compare before redemption | Binding policy must be finalized for multi-user servers |
| Expired credentials | 60-second authorization, 30-second challenge, 120-second ticket; structured reauth response | User must renew owner session |
| Lost/stolen phone | Existing owner-session revocation/device controls; no plugin credential disclosure | Pending ticket until expiry |
| Compromised Jellyfin server | Plugin key is server-held; user confirmation and Cloud audit constrain enrollment | Server can misuse its own connector authority; revoke/rotate required |
| Compromised plugin key | Key IDs, future rotation, Cloud revocation, no owner token exposure | Existing connector authority remains until revocation |
| Log leakage | Allowlist structured events; secret-leak tests; no raw headers/bodies/URLs | Operator must retain least-privilege log access |
| Ambiguous network failure | Durable reservation and idempotent attempt-status result | Delayed recovery while Cloud is unavailable |
| Downgrade to v1/v2 | Versioned QR, strict V3 endpoint selection, disabled fallback flag | Legacy rollback remains an intentional operator action |

## Logging schema

Only this allowlisted shape may be emitted for V3 pairing:

```json
{
  "event": "kaevo_pairing_v3",
  "timestamp": "RFC3339 UTC",
  "correlationId": "canonical-uuid",
  "pairingAttemptRef": "one-way-hash",
  "route": "/v3/home-connectors/pairing/redemptions",
  "transition": "authorization_active_to_redeeming",
  "httpStatus": 201,
  "outcome": "pairing_redeemed",
  "awsRequestId": "optional-aws-request-id"
}
```

The attempt reference is an irreversible hash; the raw attempt UUID is never
logged. Raw ticket secrets, proofs, authorizations, tokens, DPoP,
private keys, full URLs, query strings, request bodies, and response bodies are
forbidden in V3 logs.

## Test plan

### Cloud

- Owner DPoP authentication, session expiry, entitlement, and every binding.
- Authorization signature, audience, expiry, JTI replay, and single redemption.
- Plugin signature, key fingerprint mismatch, timestamp skew, and nonce replay.
- Idempotent same-attempt retry and different-attempt conflict.
- Status recovery after response loss and no duplicate enrollment.
- Structured error contract and log allowlist/secret-leak assertions.

### Plugin

- Key persistence and protected file mode; key-rotation preparation.
- QR signature and canonical parser; no ticket secret in diagnostics.
- Challenge expiry/replay, proof verification, atomic reservation, and races.
- Restart recovery before and after Cloud side effects.
- Safe release only before a Cloud side effect; ambiguous outcome remains
  reserved pending status resolution.
- Successful durable consumption and structured error mapping.

### iOS

- Strict V3 QR parsing and plugin fingerprint confirmation.
- One attempt UUID across authorization, challenge, completion, and recovery.
- Ticket-derived proof generated only in memory.
- Owner DPoP authorization and reauthentication UI.
- Structured error mapping, retry/status recovery, and diagnostics redaction.

### Integration and physical proof

- Happy path; expired ticket; concurrent scan; response loss; plugin restart;
  authorization replay; QR reuse; reauthentication; entitlement failure; and
  explicit V1/V2 downgrade attempt.
- Physical completion requires exactly one connector enrollment, durable ticket
  consumption, a structured rejection on reuse, and no generic HTTP 500.

## Open product decisions

1. What exact owner-facing wording and short fingerprint format should the
   native confirmation screen use?
2. What approved account-retention period applies after a connector is revoked?

## Phase B entry criteria

Phase A is approved. Phase B remains Cloud-only and must preserve v1/v2 without
unrelated identity packaging changes. The V3 signing seed is generated only by
the retained environment-scoped Secrets Manager resource, injected solely into
the API Lambda by a dynamic reference, and never appears in a template default,
source value, output, log, or client configuration. V3 remains disabled until a
reviewed dev deployment provisions that secret and its separately distributed
public verification key. No live change set or deployment is part of Phase B.
