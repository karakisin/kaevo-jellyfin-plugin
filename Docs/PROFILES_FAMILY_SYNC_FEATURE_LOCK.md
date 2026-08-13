# Profiles, Family Sync, and household media authority feature lock

- Lock ID: `KAEVO-LOCK-PROFILES-FAMILY-SYNC-2026-08-12`
- Status: **LOCKED**
- Owner and physical approver: Jefferson Sumagang
- Baseline: the latest Git commit containing this document and the paired iOS
  lock. Kaevo 4.2 (126) was physically exercised on Jefferson's iPhone 14 Pro
  Max and iPhone SE and confirmed by Jefferson on 2026-08-12 Pacific time.

## Approval gate

No person or agent may alter this contract, its Cloud implementation, its
tests, or this lock without Jefferson's explicit approval for the exact
proposed change in the current task.

Previous approval, broad cleanup or hardening permission, automated tests, a
successful deployment, an inferred emergency, or an agent-authored approval
record does not count. Unlocking, narrowing, deleting, bypassing, or weakening
this document requires the same approval.

The Requests and Download Details lock remains independent. This lock cannot
authorize changes to it. The paired iOS lock is recorded in
`Docs/PROFILES_FAMILY_SYNC_FEATURE_LOCK.md` in the iOS repository and protects
the rendered and cached client behavior.

## Locked Cloud contract

- Canonical immutable installation, household, profile, Jellyfin, connector,
  and media IDs own identity, access, writes, and readback. Names, avatars,
  ordering, and client guesses are presentation only.
- Profile Switching and Who's Watching are separate permission systems. Cloud
  returns only explicitly authorized active profile IDs and fails closed when
  authority or a binding is stale, missing, ambiguous, or conflicting.
- The authenticated installation may request protected media only for its exact
  active or explicitly switch-authorized profile. A bearer does not authorize
  an arbitrary household profile.
- Household progress reads are scoped to the exact requested and authorized
  profile while retaining explicitly selected Family Sync participants for the
  exact media item.
- Family Sync remains exact-item and exact-profile. Watching, Paused, Resumed,
  and Stopped state supports the approved approximately one-second live device
  projection while durable state remains the reliability fallback.
- A profile avatar is readable only when the requesting account may Profile
  Switch to or select that profile through Who's Watching. A user-uploaded
  avatar has household-wide precedence; an owner upload is fallback only until
  the user supplies one.
- Protected remote metadata and playback grants resolve the canonical retained
  profile-to-Jellyfin binding. They never infer the provider user from a display
  name or silently substitute the installation owner's provider identity.
- Writes are successful only after authoritative Cloud/provider confirmation.
  Ambiguous or conflicting operations remain unchanged and actionable.
- Client caches accelerate rendering only. Cloud and Jellyfin readback remain
  authoritative when two phones access the same profile.

## Protected surface

The lock applies to these paths and any replacement code serving the contract:

- `Kaevo Cloud/api/src/handler.py`
- `Kaevo Cloud/api/tests/test_household_connector_access_contract.py`
- `Kaevo Cloud/api/tests/test_household_progress_contract.py`
- `Kaevo Cloud/api/tests/test_playback_grant_contract.py`
- `Kaevo Cloud/api/tests/test_remote_request_state_contract.py`
- profile access, profile binding, avatar authority, household progress, live
  Family Sync, playback grant, connector access, and protected remote-request
  routes and tests.

## Validation baseline

- 47 affected Cloud contract tests passed for the locked implementation.
- The deployed Cloud Lambda was separately verified before the final iOS
  optimization pass.
- Jefferson physically confirmed exact per-profile content, playback, Continue
  Watching, one-second Family Sync state, profile avatars, and profile switching
  on the paired installed iOS build.

Automated tests, deployment, authoritative readback, iOS build, signing,
installation, launch, physical validation, Git commit, push, TestFlight, and
release remain separate evidence gates.

## Allowed without unlocking

Read-only inspection, diagnostics, and non-mutating tests are allowed. Unrelated
work may proceed only when it does not alter the protected contract or its
implementation. If scope is ambiguous, treat it as locked and ask Jefferson.

This is an auditable repository and agent-process lock. It does not claim
operating-system, Git-server, AWS-IAM, or cryptographic write prevention.
