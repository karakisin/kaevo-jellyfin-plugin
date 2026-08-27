# Kaevo Account Lifecycle V2

Status: implementation in progress. V1 remains available only as a rollback
path until Jefferson physically validates V2 from fresh signup through terminal
deletion.

## Why V1 is being replaced

V1 lets the iOS client reconstruct an account-deletion cleanup scope from a
fresh profile projection and local profile mappings. Account creation,
installation mapping, provider binding, and deletion therefore use different
authority graphs. A valid signed-in account can be blocked before Cloud sees a
deletion request when any projection is duplicated, stale, or incomplete.

V2 has one rule: the authenticated client may request a scope, but only Cloud
may enumerate what belongs to the account.

## Account lifecycle registry

Every V2 account owns one strongly consistent DynamoDB partition:

- partition key: immutable `account_id`
- sort key: deterministic lifecycle record key
- one lifecycle root containing schema, revision, state, owner subject, and
  household role
- one resource edge for every Kaevo account, auth identity, Cognito subject,
  household, membership, Cloud profile, profile binding, installation, and
  exact provider binding
- no display name, avatar, email address, or device-local identifier is an
  ownership key

Creation and every later lifecycle mutation write the business record and its
registry edge in the same transaction. If either write fails, neither becomes
authoritative.

The root also carries a transactionally maintained Owner-deletion guard. A
fresh household begins as `sole_member`. Inviting or joining another active
member changes it to `ownership_transfer_required` in the same transaction;
account deletion remains unavailable until ownership is transferred or the
household is again provably single-member.

## Native signup contract

1. Kaevo presents native Continue with Apple and Continue with Google actions.
2. The managed authentication surface uses Kaevo's custom authentication
   domain and the public provider application name `Kaevo`.
3. Cloud verifies the provider subject and atomically creates the lifecycle
   root, Account, AuthIdentity, household, Owner membership, first Cloud
   Profile, ProfileBinding, and their registry edges.
4. The app registers its installation and confirms the selected device-local
   profile source in one explicit completion call.
5. Success returns one `ready` receipt. Migration-review and profile-bootstrap
   screens are not valid success outcomes for a fresh V2 account.

## Deletion contract

### Preflight

The app sends only its protected account session and requested scope:

- `kaevo_only`
- `everything`

Cloud strongly reads the lifecycle registry, validates every referenced
resource by immutable key, freezes a versioned deletion plan, and returns a
durable operation identifier plus dynamic provider capability state. The app
does not send profile IDs, provider IDs, email, or local cleanup scope.

### Confirmation and execution

The user confirms the frozen operation. Cloud then advances an idempotent,
resumable operation through these phases:

1. `queued`
2. `deleting_seerr`
3. `verifying_seerr_absence`
4. `deleting_jellyfin`
5. `verifying_jellyfin_absence`
6. `deleting_cognito`
7. `verifying_cognito_absence`
8. `deleting_kaevo_graph`
9. `verifying_kaevo_absence`
10. `completed`

`everything` is selectable only when the exact paired connector reports the
separate two-way profile-deletion capability as enabled. Media libraries and
files are never lifecycle resources and are never deleted.

Every phase records a non-secret receipt. A retry resumes the same operation;
it does not build a new plan. Before deleting the exact Cognito subject, the
worker binds its verified normalized email to the exact AuthIdentity record.
The operation is terminal only after fresh Cognito lookups prove both the
subject and normalized email absent, requested provider identities are absent,
and all registered Kaevo resources are authoritatively absent. This makes the
email reusable without treating it as an ownership selector or exposing it to
the client deletion plan.

## iOS completion rule

iOS retains its protected session and all local data while the operation is
non-terminal. It clears local mappings, cached Cloud authority, and secure
session material only after a terminal `completed` receipt whose account ID
matches the authenticated account and whose requested proof fields are true.

## V1 retirement gate

V1 code is inventoried in the repository's `Legacy/AccountLifecycleV1`
directory. It must not be removed until Jefferson physically confirms:

- fresh Google signup
- fresh Apple signup
- household and first profile creation without review recovery
- provider provisioning and exact binding
- `kaevo_only` deletion
- `everything` deletion with Seerr and Jellyfin absence
- Cognito/email absence and clean recreation with the same email
