# KSEC-010B — Audit Principal Identifier Privacy

Date: 2026-07-18
Candidate base: `c0320937721cc1af7b8125b9fabdbf4b333f997a`
Branch: `security/audit-principal-privacy-2026-07-18`

## Diagnostic finding

KSEC-010B is confirmed. The security-audit data path retains stable identity and
household identifiers beyond what is required to investigate a security event.
This is a privacy and breach-impact defect; it is not evidence of an
authorization bypass.

Historical evidence created during the initial investigation reused the label
`KSEC-010A` for this privacy issue. That label remains the canonical identifier
for the earlier authoritative Cognito access-claim issuer gap. Historical
artifacts are preserved unchanged; references to audit principal privacy under
`KSEC-010A` are aliases for `KSEC-010B` only.

### Exact current exposure

The canonical `KaevoSecurityAuditTable` uses the raw `household_id` as its
partition key and `event_id` as its sort key. Records expire through DynamoDB TTL
after 400 days. The canonical template does not expose this table through a
CloudFormation output and the API has no route that reads it. The API and owner
enrollment Lambda roles can write it. No client role has audit-table access.

The main API writes these events:

| Event | Raw/stable values currently retained |
| --- | --- |
| `installation_registered` | household partition, Cognito `sub`, installation ID |
| `session_issued` | household partition, Cognito `sub`, family ID, installation ID |
| `refresh_reuse_detected` | household partition, Cognito `sub`, family ID, installation ID |
| `installation_revoked` | household partition, Cognito `sub`, installation ID |
| `connector_paired` | household or profile partition, profile ID as subject, connector ID, credential version |

Owner enrollment writes `identity_owner_enrolled` with the raw household
partition and a full unsalted SHA-256 digest of the Cognito `sub`. That digest is
stable, low-cost to correlate, and is not an acceptable privacy boundary. The
owner-enrollment audit write is part of the same five-item DynamoDB transaction
as the identity graph and therefore must remain atomic.

The Cognito claim issuer does not write the audit table, but denial logs include
the first 12 hexadecimal characters of an unsalted SHA-256 digest of the Cognito
`sub`. Those Lambda logs retain for 30 days. The API Gateway HTTP API has no
access-log configuration in the canonical template. No audit identifier is
present in CloudFormation outputs, metrics, or alarms.

Raw Cognito subjects and household/profile identifiers also exist in the
principal, membership, household, profile, installation, session, connector,
and application tables where they are required for authoritative identity,
authorization, ownership lookup, or product state. KSEC-010B does not authorize
changing those operational keys. They must never be copied into the audit
schema, logs, errors, metrics, outputs, or client responses merely for
correlation.

`Role.SUPPORT` declares a `read_security_audit` capability, but there is no
canonical route or handler that exercises it. This capability declaration does
not grant client access by itself.

## Selected privacy model

Audit actors will use a versioned pseudonymous reference:

```text
audit_principal_ref = "apr1_" + base64url(
  HMAC-SHA-256(environment audit key, canonical issuer + ":" + Cognito sub)
)
```

The full 256-bit digest is retained. The key is generated separately per
environment and stored in AWS Secrets Manager. It is not shared with playback,
DPoP, application-session, or connector credentials and is never emitted in
source, logs, errors, metrics, CloudFormation outputs, or client responses.

Household/profile/installation/session-family/connector targets use the same
secret with explicit type and environment domain separation and distinct
versioned prefixes. These references are deterministic only within one
environment. They are correlation-only values and must never be accepted as an
authentication credential, authorization claim, principal lookup key, session
key, or API input override.

The existing DynamoDB partition-key attribute name `household_id` remains for a
non-replacing migration, but its value becomes a versioned pseudonymous scope
reference. New records also include `scope_ref` so consumers do not mistake the
compatibility attribute name for raw data. No table replacement or index change
is required.

## Versioned audit schema

New records use `audit_schema_version = 1` and contain only:

- privacy-safe scope partition/reference;
- event ID and event type;
- privacy-safe actor reference and actor type;
- result and stable non-sensitive reason code when applicable;
- optional privacy-safe target reference and target type;
- request correlation reference that is not an account identifier;
- creation/occurrence time and TTL expiry.

They do not contain raw Cognito subjects, account IDs, household IDs, profile
IDs, installation IDs, connector IDs, session/family IDs, device IDs, email
addresses, tokens, DPoP material, IP addresses, user agents, or serialized detail
objects.

## Failure behavior

Privileged mutations prepare their privacy-safe audit record before modifying
state. If the audit secret cannot be retrieved or the record cannot be derived,
the operation fails closed with a generic temporary-unavailable response. The
authorization decision is not weakened.

Security-preserving denial and containment actions, such as refresh-family
revocation after token reuse, must still proceed. If derivation is unavailable,
they use a documented non-sensitive, non-correlatable fallback audit record;
they never fall back to a raw identifier or unsalted hash. Derivation failures
must not appear in client responses with secret or principal detail.

Owner enrollment continues to place the prepared privacy-safe audit record in
the same atomic transaction as the identity graph. A missing audit secret must
prevent that transaction from starting.

## Retention, deletion, and migration

New records retain the existing 400-day TTL policy. Lambda diagnostic logs
retain for 30 days. No new client deletion or read API is introduced. Historical
audit rows containing raw identifiers are a production migration concern and
must be inventoried and rewritten or removed under a separately approved,
rehearsed, rollback-safe data operation. This candidate does not scan, mutate,
or delete production or staging records.

The staged proof must verify that fresh records contain only the versioned
privacy-safe schema and that logs, responses, outputs, metrics, session records,
and unrelated tables do not receive equivalent raw identifiers.
