# Household Membership Normalization

## Scope and schema

This additive Cloud milestone introduces `HouseholdMembership` without
changing the legacy principal, identity-membership, household, profile,
session, installation, pairing, media, connector, or plugin records.

The `kaevo-cloud-${EnvironmentName}-household-memberships` table is keyed by
`household_id` and deterministic `membership_id`. A normalized active record
contains only server authority identifiers and state:

- `membership_id` — deterministic SHA-256-derived identity from `account_id`
  and `household_id`; stable across retries.
- `account_id`, `household_id`, `canonical_role`, `status`, `joined_at`,
  `updated_at`, `schema_version`.
- optional future fields, including `invited_by_account_id` and a
  `profile_access_policy_ref`; the migration writes
  `profile-binding-required-v1` as an explicit empty-profile-access boundary.
- `migration_provenance=legacy-authority-graph-v1` for this additive
  projection only.

It does not store display names, usernames, provider subjects, local profile
JSON, or client-provided authorization values.

Two transaction-only records in the same table protect invariants: an
account-household guard reserves one active normalized membership for the
pair, and an owner guard reserves one owner for the household. They are not
returned by the API as memberships.

## Authority, roles, and ownership

The server resolves this one chain:

`protected DPoP session -> AuthIdentity -> Account -> legacy authoritative graph -> HouseholdMembership -> capabilities -> profile access`.

The legacy graph must contain an active, internally consistent principal,
legacy membership, household, and profile. The principal and session account,
household, profile, role, and authorization version must agree. The existing
explicit `household.owner_principal_id` is the only ownership evidence used.
No ownership is inferred from order, email, billing, profile name, device, or
local state.

`owner`, `adult`, `teen`, and `child` normalize only through the centralized
`CanonicalRole` and `ROLE_CAPABILITIES` mapping. `admin` and `member` always
return `legacy_role_unresolved`; an unknown or contradictory authority graph
also fails closed. No handler grants capabilities with ad-hoc role-name
comparisons.

The migration rejects ambiguous optional `principal.household_ids`, competing
owner guards, malformed normalized records, and inactive normalized records.
An inactive or removed membership is historical state and is never silently
reactivated.

## Endpoint and states

`POST /v3/identity/migrate-household-membership` requires the existing
DPoP-bound protected app session and active installation. Its request body is
ignored for account, household, membership, role, capabilities, profile
access, ownership, and provider identity. The server creates only missing
normalized records and returns the `/v3/identity/me` representation.

Notable states are:

- `membership_migration_completed` and `already_normalized`.
- `household_membership_migration_required` from `/v3/identity/me` after
  Account/AuthIdentity migration but before membership normalization.
- `account_migration_required`, `household_authority_missing`,
  `household_authority_ambiguous`, `legacy_role_unresolved`,
  `ownership_conflict`, `membership_conflict`,
  `membership_migration_not_required`, and `manual_review_required`.

After normalization, `/v3/identity/me` returns account/auth identities,
active household, stable membership ID, canonical role, centrally resolved
capabilities, device/installation context, and `migration_state`.

## Atomicity, idempotency, and rollback

The endpoint uses one DynamoDB transaction to conditionally add the
membership, uniqueness guard, owner guard when needed, and completed audit
event. A concurrent caller rereads the deterministic keys without replaying
the already-verified DPoP proof. It therefore converges to
`already_normalized` if the same valid migration won, or returns a conflict
without overwriting existing state.

Rollback before later data depends on this membership consists only of
removing the additive normalized membership and its matching guards through a
separately authorized operational procedure. It must not change the legacy
authority graph, and it is no longer safe once later authoritative data refers
to the normalized membership.

## Profile-access boundary and future work

This milestone returns `profile_access: []`. It neither binds nor guesses
cloud/local profile mappings, and does not expose a visible profile switch
until a later server-authorized binding model exists. Local iOS JSON is not
authority. Future invitations and profile binding must create separate,
owner-authorized records and resolve access server-side.

## Audit and offline planning

Privacy-safe audit events cover attempted, completed, already-normalized,
ambiguous-authority, unresolved-legacy-role, ownership-conflict,
membership-conflict, and manual-review outcomes. Audit references are derived
by the existing privacy-safe audit writer; tokens, DPoP material, provider
credentials, passwords, emails, and raw sensitive claims are not written.

Use `scripts/plan-household-membership-normalization.py --input <sanitized.json>`
for an offline JSON plan. It defaults to dry-run, accepts `--subject` and
`--max-records`, identifies admin/member, missing authority, duplicate
candidates, and multiple owners, and reports zero write operations. It has no
AWS client and rejects `--execute`; do not run it against live resources in
this milestone.
