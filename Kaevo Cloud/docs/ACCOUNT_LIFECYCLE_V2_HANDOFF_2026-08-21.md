# Kaevo Account Lifecycle V2 Failure Handoff

Date: 2026-08-21 America/Los_Angeles (Production evidence continues into
2026-08-22 UTC)

Status: **BLOCKED — physically reproduced; no deletion occurred**

This document is the factual handoff for a new engineering conversation. It
separates observed evidence, attempted remediations, current implementation,
and remaining work. It must not be treated as proof that account deletion is
working.

## 1. Product outcome being pursued

Kaevo needs one authoritative account lifecycle from signup through terminal
deletion.

The user must be able to open **Settings -> Kaevo Account -> Delete Kaevo
Account** and choose one of two server-derived scopes:

1. `kaevo_only`
   - Delete the Kaevo account.
   - Delete the Cognito identity/email association.
   - Delete every Kaevo Cloud profile and account-owned Cloud resource.
   - Do not require Jellyfin, Seerr, a Home Connector, or Remote Access.
   - Preserve device-local playback/history data until Cloud reports terminal
     completion; then clear account-scoped local authority/session state.
2. `everything`
   - Perform everything in `kaevo_only`.
   - Additionally delete every exactly and immutably linked Seerr and Jellyfin
     user.
   - Enable this scope only when the exact paired plugin reports the separate
     two-way profile-deletion capability.
   - Never delete Jellyfin libraries or media files.

This physical test account intentionally has **no Jellyfin connection**. Its
`kaevo_only` deletion must therefore work without any connector capability.
`everything` may correctly be unavailable.

Success is not a button response, navigation back to Welcome, or accepted
request. Success requires a terminal Cloud receipt and fresh absence proof for
the requested resources, including separate Cognito subject and normalized
email absence so that the address can create a new Kaevo account.

## 2. Current latest failure — exact evidence

Physical device:

- iPhone SE
- device identifier: `97584A99-FC6A-5B63-BD54-EA5EB565FD8C`
- bundle: `com.sumagang.kaevo`
- app version/build: Kaevo 4.2 (134), ProductionDebug
- screenshot: `/Users/jeffersonsumagang/Downloads/Screenshot 2026-08-21 at 7.28.22 PM.png`

The screenshot reports:

> Deletion plan is unavailable
>
> Kaevo Cloud could not safely migrate this existing account: Kaevo Cloud
> returned HTTP 400. Nothing was deleted.

The attached redacted device console proves this exact sequence:

1. `POST /v4/account-lifecycle/deletion-preflights`
2. HTTP `409`
3. body state `lifecycle_migration_required`
4. `POST /v4/account-lifecycle/migrate-existing`
5. HTTP `400`

The Production migration Lambda log proves the server reason:

```text
2026-08-22T02:28:11.075Z
account_lifecycle_v2_migration_failed reason=audit_unavailable
request_id=6d793076-8395-4f59-aac8-df8c4ba945f8
```

The V2 registry remains empty after the attempt:

```json
{"Count":0,"ScannedCount":0}
```

Therefore:

- authentication and DPoP reached the V2 migration Lambda;
- the named-stage path fix is active;
- migration stopped before its atomic registry transaction;
- no frozen deletion plan was created;
- no account, profile, Cognito identity, Jellyfin user, or Seerr user was
  deleted by this attempt.

### Immediate root cause of the current HTTP 400

`account_lifecycle_v2_migration.py` calls `prepare_audit_item(...)` before its
atomic DynamoDB write. `security_audit.py` calls `principal_ref(...)`, which
requires the environment variable `EXPECTED_COGNITO_ISSUER`.

The deployed Production migration Lambda environment contains
`AUDIT_REFERENCE_SECRET_ARN`, `SECURITY_AUDIT_TABLE`, and all migration tables,
but **does not contain `EXPECTED_COGNITO_ISSUER`**.

That missing variable raises `AuditReferenceError`, which migration converts
to `LifecycleV2MigrationError("audit_unavailable")`, then returns HTTP 400.

The same omission exists in both infrastructure definitions for the migration
function:

- `Kaevo Cloud/infra/template.yaml`
- `Kaevo Cloud/infra/account-lifecycle-v2-migration-production.yaml`

The Production issuer already used elsewhere is:

```text
https://cognito-idp.us-west-2.amazonaws.com/us-west-2_alttn6ama
```

The next engineer should verify this exact diagnosis with a regression test,
add the issuer through the owning CloudFormation configuration (not an
untracked console-only change), deploy the migration stack, and then repeat the
existing-account migration/preflight. Do not begin deletion during that
diagnostic deployment.

## 3. V1 versus V2

### Account Lifecycle V1 — legacy rollback path

V1 is still present only as a rollback path. Its inventory is documented in:

- `Kaevo Cloud/Legacy/AccountLifecycleV1/README.md`
- `iOS/Legacy/AccountLifecycleV1/README.md`

V1 lets the iOS client reconstruct deletion scope from a fresh profile
projection, local profile mappings, cached Cloud identity, and provider status.
Cloud then uses legacy `/v3/identity/*` enrollment/migration/account-deletion
routes and legacy provider command adapters.

V1 retirement targets include:

- iOS `KaevoOwnerSessionCoordinator.deleteAccount`
- `accountDeletionLocalPlanProvider`
- `KaevoVerifiedAccountDeletionLocalPlan`
- profile-mapping-derived local cleanup
- V1 request/status polling models
- Cloud `identity_enrollment.py`
- `/v3/identity/migrate*`
- `/v3/identity/profile-mappings/create-and-confirm`
- `_account_deletion_plan`
- `_execute_account_deletion_provider_cleanup`
- `_execute_account_deletion`
- `DELETE /v3/identity/account`
- `GET /v3/identity/account-deletions/{attempt_id}`

Why V1 is being replaced:

- account creation, local profile mapping, provider binding, and deletion do
  not use one authority graph;
- stale, missing, or duplicated projections can block deletion before Cloud
  receives an authoritative operation;
- the UI previously mixed profile deletion and account deletion;
- provider capability could incorrectly block Kaevo-only deletion;
- returning to Welcome did not prove Cloud/Cognito absence.

Do **not** remove V1 yet. Jefferson explicitly required V2 physical validation
before V1 deletion.

### Account Lifecycle V2 — current active redesign

V2 has one authority rule:

> The protected client may request a scope, but only Cloud may enumerate the
> immutable resources owned by the authenticated account.

V2 uses a strongly consistent DynamoDB partition keyed by immutable
`account_id`. The registry root and resource edges represent the account,
AuthIdentity, Cognito subject, principal, household/membership when owned,
Cloud profiles, profile bindings, installations, and exact provider bindings.
Email, display name, avatar, and device-local profile names are never ownership
keys.

New V2 accounts are supposed to write their business graph and lifecycle edges
atomically during signup. Existing V1 accounts use an explicit protected
migration endpoint that reads and proves the exact legacy graph, then writes
the V2 root, resource edges, and privacy-safe audit record in one transaction.

## 4. Intended V2 signup flow

1. Native Kaevo account screen presents email/password, Continue with Apple,
   and Continue with Google.
2. Managed provider presentation uses Kaevo's branded authentication domain.
3. Cognito authenticates the provider subject.
4. Cloud atomically creates:
   - Account
   - AuthIdentity
   - household
   - Owner membership
   - first Cloud Profile
   - ProfileBinding
   - V2 lifecycle root and all registry edges
5. The app registers the installation-bound key and protected session.
6. The device user explicitly chooses/connects the retained local profile.
7. Cloud returns one `ready` result.
8. A fresh V2 signup must not land in legacy migration review or first-profile
   repair.

Fresh Google signup, fresh Apple signup, subscription/offer-code behavior, and
clean recreation after terminal deletion remain separate physical release
gates.

## 5. Intended V2 existing-account migration and deletion flow

### Migration and preflight

1. iOS validates or rotates its installation-bound protected owner session.
2. iOS sends only:
   - protected bearer session
   - DPoP proof for the exact URL
   - requested scope (`kaevo_only` or `everything`)
3. `POST /v4/account-lifecycle/deletion-preflights` strongly reads the V2
   registry.
4. If the account predates V2 and no registry exists, Cloud returns
   `409 lifecycle_migration_required`.
5. iOS calls `POST /v4/account-lifecycle/migrate-existing`.
6. Migration selects the account only from the protected session and reads the
   exact canonical V1 graph by immutable keys.
7. Migration prepares the privacy-safe audit record.
8. One DynamoDB transaction writes the registry root, every proved resource
   edge, the audit record, and snapshot condition checks.
9. iOS retries preflight.
10. Cloud validates the registry and freezes a versioned deletion plan.
11. Cloud returns the durable operation ID, plan digest, scope, immutable
    resource list, and dynamic provider capability status.

The current failure occurs at step 7 because the migration Lambda cannot build
the audit reference without `EXPECTED_COGNITO_ISSUER`.

### Confirmation and durable execution

After the user confirms the exact frozen plan, V2 is designed to advance one
idempotent operation through:

1. `queued`
2. `deleting_seerr` (only for `everything` and only when exactly bound)
3. `verifying_seerr_absence`
4. `deleting_jellyfin`
5. `verifying_jellyfin_absence`
6. `deleting_cognito`
7. `verifying_cognito_absence`
8. `deleting_kaevo_graph`
9. `verifying_kaevo_absence`
10. `completed`

Retries must resume the same durable operation and frozen plan. They must not
reconstruct scope from current local mappings.

### iOS completion rule

iOS must retain the protected session and local state while the operation is
non-terminal. It may clear account-scoped mappings, cached authority, and
Keychain session material only after a terminal `completed` receipt whose
account ID and requested absence proofs match the authenticated operation.

## 6. Attempt count and intervention history

An exact count of every physical button tap is not available from source or
Cloud logs. It would be dishonest to invent one.

What can be proved from this conversation:

- **12 screenshot-documented deletion checkpoints/error states** between
  2026-08-20 00:59 and 2026-08-21 19:28.
- Several additional verbal retries without screenshots, including buttons
  that appeared to do nothing, Kaevo-only retries, Everything retries, and one
  flow that returned to Welcome but later proved the Cloud account remained.
- **8 distinct engineering intervention cycles** related to account deletion
  and lifecycle authority are documented below.

### Intervention 1 — V1 deletion choices and provider scope

- Added Kaevo-only versus Everything choices.
- Defined Everything as Kaevo + exact linked Jellyfin + exact linked Seerr.
- Preserved libraries/media.
- Restored deletion entry points under profile/account options.
- Result: UI existed, but completion and provider linkage were inconsistent.

### Intervention 2 — exact provider linkage and capability display

- Changed UI toward immutable provider linkage rather than display-name
  matching.
- Added dynamic display of linked/unavailable provider status.
- Added separate two-way profile-deletion capability semantics.
- Result: provider state became clearer, but stale/missing plugin capability
  still blocked or confused deletion.

### Intervention 3 — Jellyfin plugin option and releases

- Added **Allow two-way profile deletion** separately from **Allow Kaevo to
  delete media**.
- Corrected plugin configuration wording, checkbox layout, and spacing.
- User physically confirmed plugin 0.3.9.0 and that the option was on.
- User later approved publishing plugin 0.3.10.
- Result: provider capability became explicit, but the current test account has
  no Jellyfin connection, so the plugin cannot be the cause of Kaevo-only
  deletion failure.

### Intervention 4 — consolidated account deletion and V1 recovery work

- Consolidated profile/account deletion UX toward Kaevo Account.
- Attempted to remove Cloud profiles, Kaevo account/email identity, and exact
  providers from one account flow.
- Added safer fail-closed messages and retained sessions after failures.
- Result: one deletion appeared to finish and returned to Welcome; later
  sign-in proved Cloud identity/profile state still existed. That result must
  be considered a regression, not successful deletion.

### Intervention 5 — Account Lifecycle V2 redesign

- Introduced server-owned lifecycle registry, frozen plans, durable operation
  state, provider receipts, status token, worker, enrollment, migration, and
  registry synchronization modules.
- Archived V1 inventories without removing the rollback implementation.
- Added the V2 iOS client models/coordinator and deletion UI integration.
- Result: architecture is present but has not completed a physical migration
  or deletion.

### Intervention 6 — empty registry classification

- Production V2 lifecycle table was found empty.
- `account_lifecycle_v2_service.py` previously treated an empty registry as an
  ambiguous lifecycle root, which prevented iOS from invoking migration.
- Changed empty registry handling to `lifecycle_root_missing`, mapped by the
  API to `409 lifecycle_migration_required`.
- Focused Cloud suite reported 35 passing tests at that stage.
- Deployed the Production V2 API Lambda.
- Result: the app could recognize migration was required, but subsequent
  protected-session/path issues still blocked migration.

### Intervention 7 — iOS sensitive-session freshness gate

- Added `ensureFreshProtectedSession()` before V2 preflight in
  `KaevoOwnerSessionCoordinator.prepareAccountLifecycleV2Deletion`.
- Added an iOS source-order regression test.
- Focused account deletion and V2 iOS suites passed.
- Built, signed, installed, and launched Kaevo 4.2 (134) on the iPhone SE.
- Result: physical retry still failed. The generic owner-device/session probe
  also reports response decoding failures and uses legacy wording such as
  Remote Access; it must not be used as proof that the V2 protected path is
  healthy.

### Intervention 8 — full trace, safe diagnostics, and named-stage fix

- Attached a redacted physical-device console.
- Proved `/v3/identity/me` and profile mappings returned HTTP 200.
- Proved V2 preflight returned one API 4xx and migration was not invoked.
- Added privacy-safe lifecycle session rejection logs containing only method,
  normalized route, stage, and rejection category.
- A Production probe revealed API Gateway sent:

  ```text
  rawPath=/production/v4/account-lifecycle/deletion-preflights
  stage=production
  ```

- The isolated V2 authenticator had appended that raw path to a public base URL
  that already ended in `/production`, creating a mismatched DPoP target; its
  router also expected the stage-less path.
- Added one shared stage-path normalizer used by authentication and routing.
- Added Production-shaped DPoP and routing tests.
- Focused Cloud suite passed 48/48.
- Deployed both Production V2 preflight and migration Lambdas.
- Result: this intervention worked for its exact boundary. The latest physical
  retry now reaches migration, which exposes the next independent blocker:
  `audit_unavailable` caused by missing `EXPECTED_COGNITO_ISSUER`.

## 7. Current deployment and repository state

### iOS

- repository: `/Volumes/HomeLab/AppData/Kaevo Pairing V3/iOS`
- branch: `feature/pairing-v3-clean-architecture`
- observed HEAD before this handoff: `c994c56`
- worktree: heavily dirty; contains user work and lifecycle changes
- installed physical build:
  `/Volumes/Apple Developer/KaevoBuilds/Kaevo-4.2-lifecycle-v2-session-refresh-device/Build/Products/ProductionDebug-iphoneos/iOS Kaevo v2.app`
- focused test result:
  `/Volumes/Apple Developer/KaevoBuilds/Kaevo-lifecycle-v2-session-refresh-tests/Logs/Test/Test-Kaevo Production-2026.08.21_18-58-36--0700.xcresult`

Relevant iOS changes include:

- `iOS Kaevo v2/AccountLifecycleV2/` (untracked directory)
- `iOS Kaevo v2/Cloud/KaevoOwnerSessionCoordinator.swift`
- `iOS Kaevo v2/Cloud/KaevoCloudClient.swift`
- `iOS Kaevo v2/Cloud/KaevoCloudModels.swift`
- `iOS Kaevo v2/Screens/Settings/SettingsScreen.swift`
- `iOS Kaevo v2Tests/KaevoAccountLifecycleV2Tests.swift` (untracked)
- `iOS Kaevo v2Tests/KaevoAccountDeletionTests.swift`
- `iOS/Legacy/AccountLifecycleV1/README.md` (untracked archive inventory)

### Cloud/plugin

- repository: `/Volumes/HomeLab/AppData/Kaevo Pairing V3/Plugin`
- branch: `release/0.3.8`
- observed HEAD before this handoff: `0bc7005`
- worktree: heavily dirty; branch was ahead of origin; lifecycle modules and
  tests are untracked

Relevant Cloud changes include:

- `Kaevo Cloud/api/src/account_lifecycle_v2*.py` (untracked modules)
- `Kaevo Cloud/api/tests/test_account_lifecycle_v2*.py` (untracked tests)
- `Kaevo Cloud/docs/account-lifecycle-v2.md` (untracked)
- `Kaevo Cloud/Legacy/AccountLifecycleV1/README.md` (untracked)
- `Kaevo Cloud/infra/template.yaml`
- `Kaevo Cloud/infra/account-lifecycle-v2-migration-production.yaml`
- `Kaevo Cloud/scripts/prepare-account-lifecycle-v2-production-template.py`

Direct Production code deployments performed during the latest diagnosis:

- `kaevo-cloud-production-account-lifecycle-v2-api`
  - last modified: `2026-08-22T02:24:51Z`
  - state/update: Active / Successful
- `kaevo-cloud-production-account-lifecycle-v2-migration`
  - last modified: `2026-08-22T02:25:15Z`
  - state/update: Active / Successful

These were scoped `update-function-code` deployments constructed from the
currently deployed artifacts with only the relevant lifecycle files replaced.
The next engineer must reconcile source, generated template, owning
CloudFormation stacks, and deployed artifacts before calling the state durable.

## 8. Exact current account evidence

Redacted diagnostics identified:

- account ID: `acct_4DO82L_EvUFHRv9Nb_qVGN9ep_61vGRM`
- active household ID: `hh_g4HhjH26GqsrITpUSwarTA3INvY5s40W`
- principal/Cognito subject: `a8e1f360-b031-70ef-773a-9c812e9bb69a`
- identity/profile-mapping responses: HTTP 200
- profile mapping count reported by current identity: 2
- V2 lifecycle registry record count: 0

Two active installation records were observed for the same account/household:

- `3100c7ae-abf9-4cde-ae57-6ef02db6d735`
- `c1d1104d-40f5-47a2-9dfa-7045a28cea73`

Multiple access/refresh records and refresh families also exist. This may be
normal across reinstall/sign-in cycles, but it must be evaluated by immutable
installation/session IDs rather than cleaned up by email. It is not the cause
of the latest HTTP 400 because the migration request authenticated and reached
audit preparation.

## 9. Required next steps for the new engineer

Do these in order. Do not skip directly to another physical deletion attempt.

1. Start read-only:
   - prove both repositories, branches, HEADs, and dirty boundaries;
   - do not use `git add -A`, reset, checkout, or clean;
   - distinguish user changes from lifecycle work.
2. Reproduce the current `audit_unavailable` in a Production-shaped unit test:
   - named stage in `rawPath`;
   - valid DPoP-bound session;
   - exact legacy graph;
   - audit preparation with Production environment configuration.
3. Add `EXPECTED_COGNITO_ISSUER` to the migration function's owned
   infrastructure definitions and generated/deployment contract tests.
4. Verify the migration IAM role can read the exact audit secret and transact
   against the audit table. Do not assume the environment fix proves IAM.
5. Deploy through the owning CloudFormation path and verify no route/integration
   drift.
6. Invoke only preflight/migration from the physical app:
   - expect initial `409 lifecycle_migration_required`;
   - expect migration 200/201 `ready`;
   - expect the retry preflight to return a frozen plan;
   - stop before final confirmation and inspect the registry partition.
7. For this unpaired account, verify `kaevo_only` is selectable and
   `everything` is unavailable without calling Jellyfin or Seerr.
8. Only after the frozen plan is correct should Jefferson explicitly confirm
   deletion.
9. Observe the durable operation through terminal completion.
10. Verify fresh absence independently:
    - Lifecycle operation completed with proofs;
    - Account/AuthIdentity/principal/membership/profile/binding/installation
      graph absent as specified;
    - Cognito subject/email association absent;
    - no V2 registry active resources remain;
    - same email can perform a completely fresh signup;
    - local-only user data was preserved as designed;
    - no Jellyfin/Seerr command was attempted for `kaevo_only`.
11. Separately test `everything` using an account with exact provider bindings
    and an enabled two-way deletion capability.
12. Keep V1 until Jefferson explicitly approves retirement after the complete
    physical matrix.

## 10. Do-not-regress rules

- Never enumerate or delete ownership by email, display name, avatar, provider
  username, or local profile name.
- Never require Jellyfin/Seerr/Remote Access for `kaevo_only`.
- Never let the app send authoritative profile/provider cleanup IDs.
- Never clear local secure state before terminal Cloud completion.
- Never claim deletion because the app returned to Welcome.
- Never remove V1 before the stated physical retirement gate.
- Never delete media files or libraries as part of account lifecycle.
- Never silently fall back from V2 to V1 after V2 preflight begins.
- Never treat tests, a successful deploy, or a responsive button as physical
  end-to-end validation.

## 11. Suggested opening request for the new conversation

Use this document as the contract, then ask the next engineer:

> Read `Kaevo Cloud/docs/ACCOUNT_LIFECYCLE_V2_HANDOFF_2026-08-21.md` completely.
> Start read-only and verify every current claim against the repositories and
> Production state. Do not patch the UI or reuse V1 planning. Reproduce and fix
> the V2 migration `audit_unavailable` root cause through the owning
> infrastructure, then stop at a physically verified frozen Kaevo-only plan
> before any deletion. Preserve all dirty worktree changes and report every
> unverified boundary honestly.
