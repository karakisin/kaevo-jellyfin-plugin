# Kaevo Cognito authoritative access-token claims

Date: 2026-07-18

Finding: **KSEC-010A — High**

Operational status: **remediated in canonical source; open until staged with real Cognito tokens**

## Root cause

The accepted security candidate required Kaevo tenant and authorization claims,
but its Cognito user pool had no pre-token-generation trigger or other trusted
claim issuer. A real Cognito user therefore received standard claims only and
failed closed at the API with `invalid_identity_claims`. Mutable Cognito custom
attributes would not be an acceptable authority for household authorization.

## Canonical remediation

Cognito pre-token-generation event **V2_0** now invokes a read-only claim issuer.
For the main iOS/tvOS app client it uses the opaque Cognito `sub` to consistently
read and validate these DynamoDB records:

| Record | Key | Authority |
|---|---|---|
| Principal | `principal_id = sub` | account, household, role, current authorization version, allowed profile IDs, active/revoked state |
| Membership | `principal_id = sub` | the human principal's current login profile and matching role/version |
| Household | `household_id` | account relationship, active state, authoritative owner |
| Identity profile | `profile_id` | account/household relationship, owner binding, active state |

Only after the entire graph agrees does the issuer add these access-token
claims: `account_id`, `household_id`, `profile_id`, `role`, `authz_version`, and
`identity_schema_version=1`. It suppresses those names from ID tokens. Supported
human roles are exactly `owner`, `adult`, and `child`; `support` and all machine
roles fail closed. Cognito attributes, client metadata, request bodies, provider
data, and app-supplied identifiers are ignored as authority.

The issuer can only read the four authority tables. It has no table writes, S3,
provider, media, session-secret, or administrative permission. Cognito pool and
client identity are checked from `DescribeUserPool` and
`DescribeUserPoolClient`. Cognito IAM does not offer app-client resource
granularity for these describe calls, so those two read-only actions use
`Resource: "*"`; runtime pool/client-name checks and the Lambda invocation
source account/user-pool ARN pattern provide the compensating boundary.

## Smallest secure owner bootstrap

No authoritative owner bootstrap existed. The implementation therefore uses a
second, short-lived enrollment-only Cognito app client and a separate narrowly
scoped Lambda:

1. Cognito creates/authenticates the human user.
2. The enrollment client receives a standard access token with all Kaevo claim
   names suppressed.
3. API Gateway verifies that token against only the enrollment client.
4. `POST /v2/identity/enroll-owner` revalidates `sub`, `iss`, `client_id`,
   `token_use=access`, `exp`, `iat`, and `auth_time`.
5. The server generates account, household, profile, principal, and audit IDs.
6. One DynamoDB transaction conditionally creates principal, membership,
   household, profile, and non-secret audit records.
7. Replay returns the existing valid graph; conflicting or partial state fails
   closed. The route is throttled.
8. The client must authenticate with the main app client again. Only then can
   the read-only trigger issue Kaevo claims.

The enrollment token cannot authorize normal household APIs because their JWT
authorizer accepts the main app client, and application code also rejects ID
tokens, the enrollment client, expired tokens, wrong issuers, and unsupported
schema versions.

Adult invitation, recovery/replacement identity rebinding, and promotion of a
child profile to a login identity require separate reviewed, recent-owner-auth
workflows. They are intentionally not fabricated by the issuer. A child profile
without login remains a household profile record, not a Cognito user. Home
connectors, plugins, devices, and app installations remain P-256/DPoP machine
identities.

## Request-time revocation

API Gateway verifies JWT authenticity, but Kaevo does not treat a signed role as
sufficient. Every protected human request loads the current principal with a
consistent read and rechecks `sub`, account, household, profile membership,
role, active/revoked state, `authz_version`, capability, target ownership, and
recent owner authentication where required. Increasing `authz_version`, changing
role/membership, or revoking the principal is rejected on the next protected
request. The intended application-level stale-authorization window is therefore
one request/read round trip; the cryptographic access token remains valid for at
most 15 minutes but cannot bypass the current-record check.

## Failure and privacy behavior

Missing, malformed, unsupported, inconsistent, disabled, deleted, pending, or
unavailable authority fails token issuance with a generic authentication
failure. No partial identity or implicit owner is created. Logs contain only a
generic result, request correlation value, short subject hash, and duration.
Tests plant canary secrets and complete identifiers and confirm they do not
appear in logs.

## Feature-plan decision and deployment gate

Cognito access-token customization with pre-token-generation V2 requires the
Essentials or Plus feature plan. The canonical template makes the tier explicit
and defaults to `ESSENTIALS`, but **no AWS deployment or paid-plan change is
authorized by this source work**. The owner must confirm current-account pricing
and the selected tier before a fresh Phase 2 preflight or any AWS write.

The previous external Phase 2 derived template predates this architecture and is
marked superseded. A new derivation, hashes, denylist scan, SAM validation, cost
review, and Add-only change-set inspection are required under separate approval.

## Local proof

Adversarial tests cover authoritative claim issuance, ignored Cognito/client
forgeries, missing/disabled/revoked/unsupported/mismatched graphs, missing and
stale versions, wrong pool/client, ID-token substitution, unsupported trigger
events, dependency failure, log canaries, server-generated atomic enrollment,
replay, and concurrent enrollment convergence. Operational closure still
requires staged owner authentication, fresh-token issuance, version/revocation
drills, and recovery/invitation workflow proof with synthetic identities.
