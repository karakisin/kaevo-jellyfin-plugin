# Account Foundation

Account Foundation introduces additive, server-authoritative Account and
AuthIdentity records for future Kaevo identity work. It does not migrate local
profiles, alter household UX, or change protected-session, pairing, media, or
connector behavior.

## Canonical roles

The only canonical roles are `owner`, `adult`, `teen`, and `child`. New APIs
resolve their capabilities from `api/src/account_foundation.py`; clients can
display the result but cannot submit or grant it.

Existing server roles map without reinterpretation: `owner -> owner`,
`adult -> adult`, and `child -> child`. The former iOS-local `admin` and
`member` labels have no unambiguous canonical equivalent. They are never
written to the normalized model; a future owner-confirmed migration must
explicitly choose a canonical role for each such record.

## Identity binding

An `AuthIdentity` binds exactly one `provider + provider_subject` to one
Account. Its DynamoDB primary key is a non-reversible SHA-256 digest of that
opaque pair, so provider subjects are not exposed by the API. The binding is
created atomically with a newly enrolled Account and identity graph. Email is
optional metadata only and is never used to merge accounts.

## Read-only context

`GET /v3/identity/me` requires the existing DPoP-bound protected access
session. It accepts no account, household, role, or profile parameters. The
server resolves the Account, AuthIdentity binding, current identity graph,
capabilities, active profile access, and bound device from server records.
Older accounts without the additive Account/AuthIdentity records receive a
fail-closed migration-required response until a separately reviewed backfill
is implemented.

## Existing-account backfill

`POST /v3/identity/migrate-existing-account` is the controlled write path for
an already authenticated, DPoP-bound installation. It accepts no account,
household, role, profile, or provider-subject input. The server validates the
protected session against the current principal, membership, household, and
profile authority graph, then reuses that principal's existing immutable
`account_id`. It never derives an account ID from email, username, display
name, or local profile data.

The operation creates only missing Account/AuthIdentity records in a DynamoDB
transaction with its `identity_migration_completed` audit event. Existing
valid normalized records are not changed. A repeated request returns
`already_migrated`; a transaction race re-reads the records and converges on
that same result. A provider binding owned by another account, a malformed
normalized record, a missing authority graph, or `admin`/`member` role data
stops the migration with a conflict or manual-review state. Rollback is the
absence of the additive records: the legacy authority graph, installations,
sessions, and media data are never modified.

Every resolvable attempt receives privacy-safe audit events for attempted,
completed, already-migrated, rejected, conflict, or manual-review outcomes.
Those records use the existing pseudonymous audit references and include no
tokens, passwords, raw provider subjects, or email addresses.

### Offline dry-run

`scripts/plan-existing-account-backfill.py` reads a sanitized local JSON
authority-graph export and emits a machine-readable no-write plan. It supports
`--subject` and `--max-records`; it has no AWS client and rejects `--execute`.
The report contains an opaque subject reference, proposed stable account ID,
state, and proposed operations only. It must be reviewed before invoking the
protected endpoint. The utility does not inspect local iOS profiles, and email
matching is prohibited because email is mutable metadata rather than identity.
