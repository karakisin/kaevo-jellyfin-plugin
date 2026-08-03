# Authoritative Profile Binding Foundation

## Scope

This Cloud-only layer adds explicit `Profile` and `ProfileBinding` records.
It does not read, upload, map, delete, or alter local iOS profile JSON,
watch history, recommendations, preferences, avatars, or identifiers. Matching
names never establish identity. A future migration needs a separately reviewed,
owner-confirmed mapping record using an opaque source reference; that record
must not become a binding until confirmed.

## Records and identifiers

`Profiles` stores server-issued `prf1_<UUID>` IDs, household ID, display name,
canonical profile type (`adult`, `teen`, or `child`), matching age
classification, active status, timestamps, schema/provenance/migration state,
and a `profile-protection-unconfigured-v1` placeholder. It stores no PIN or
biometric material. A profile’s household is immutable because the creation
route never updates or reassigns profiles.

`ProfileBindings` is keyed by `(account_id, profile_id)` and carries a
deterministic `pbd1_` hash binding ID, household ID, access level, status,
granting account, timestamps, schema, and provenance. This primary key gives
one active binding per account-profile pair; an inactive or revoked row is
historical and cannot be silently reactivated.

## Access policy

`view` permits minimal server-authorized visibility, `switch` permits
authorized activation, and `manage` permits permitted profile-settings work.
Only profile creation produces a `manage` binding, and only for its authorized
creator. The narrow binding route permits an authorized household manager to
grant only explicit `view` or `switch` to a separate active member of the same
household. It cannot self-elevate, grant `manage`, bind an unknown/inactive
account, or cross household boundaries.

Household ownership does not implicitly grant identity ownership or access to
another adult profile. Adult, teen, and child profiles remain private until a
binding exists; child/teen access is never implied by profile type. A removed
member fails the active normalized-membership resolver and receives no profile
access.

## APIs and resolution

`POST /v3/identity/profiles` requires the DPoP-bound protected session, an
active normalized account/membership, and `household.manage`. It accepts only
safe presentation/classification values, issues the profile ID server-side,
and atomically writes the Profile, creator `manage` binding, and audit item.

`POST /v3/identity/profiles/{profileId}/bindings` uses the same authority and
allows an explicit `target_account_id` plus `view`/`switch` level only. The
target must have an active normalized Account and same-household membership.
Other caller-supplied account, household, role, capability, ownership, and
binding identifiers do not decide authorization.

`GET /v3/identity/me` now resolves only active bindings belonging to the
authenticated account, verifies each referenced active same-household Profile,
and returns safe profile metadata. No bindings means `profile_access: []`.
Profile switching capability is visible only when two or more explicit active
`switch`/`manage` bindings exist.

## Integrity, audit, and rollback

Writes are conditional DynamoDB transactions. Profile creation includes its
initial binding and audit atomically; binding creation includes its audit
atomically and re-reads after a transaction conflict to converge on an
already-existing active binding. Existing values are never overwritten.

Audit events cover creation/rejection, binding creation/already/rejection,
cross-household requests, unauthorized access levels, resolution, conflicts,
and manual review. The existing privacy-safe writer is used: no tokens,
passwords, DPoP material, provider credentials, PINs, or local profile data.

Rollback before dependent authoritative data exists consists only of removing
the additive Profile/Binding rows through a separately authorized operation;
it must never change legacy identity or local-profile data.

## Offline planning

`scripts/plan-profile-binding-migration.py --input <fixture.json>` is a
fixture/export-only dry-run planner. It reports ambiguous ownership, duplicate
names without treating them as identity, missing household membership,
unresolved classification, and malformed candidates. It has no AWS client,
performs zero writes, supports `--max-records`, and rejects `--execute`.
