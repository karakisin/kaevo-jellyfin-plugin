# Local Profile to Cloud Profile Mapping Foundation

## Scope and privacy boundary

This additive foundation allows a signed-in installation to review and explicitly
confirm an association between one existing local Kaevo profile and one
server-authorized Cloud Profile. It is neither automatic matching nor a sync
system. It never reads, uploads, stores, or transforms local profile JSON,
watch history, recommendations, preferences, PINs, avatars, parental settings,
or media state.

The iOS client creates an opaque `lps1_` source identifier from a
device-local installation scope plus the existing local profile identifier. The
Cloud API receives only that one-way source identifier. Names, profile type,
and age classification are presentation fields for the confirmation screen,
never identity evidence.

The mapping is deliberately distinct from `ProfileBinding`: bindings control
Cloud access; mappings document a user-approved link for one installation.
There is no global matching, cross-device link, account merge, or silent
replacement behavior in this milestone.

## Cloud record and APIs

`KaevoProfileMappingsTable` is keyed by `(installation_id,
local_profile_source_id)`. A confirmed record stores a server-derived account,
household, Cloud Profile ID, deterministic `pmp1_` mapping ID, timestamps, and
the `explicit_user_confirmation_v1` method. It uses encryption, point-in-time
recovery, and retain policies like the adjacent identity records.

All routes require the existing DPoP-bound protected application session and
derive installation, account, household, and profile authority on the server:

- `GET /v3/identity/profile-mappings` lists only mappings for that installation
  and authenticated account/household context. A confirmed mapping whose
  profile access is no longer usable is returned as `unresolved`; the record is
  preserved for review.
- `POST /v3/identity/profile-mappings/preview` returns only the caller's
  server-authorized Cloud Profiles and the permitted confirmation actions. It
  neither writes a record nor asserts a match.
- `POST /v3/identity/profile-mappings/confirm` requires
  `explicit_confirmation: true` and `switch` or `manage` access to the selected
  Cloud Profile. The write is conditional and atomic with its privacy-safe
  audit event. Repeating the same decision converges to
  `mapping_already_confirmed`; choosing a different target conflicts.
- `POST /v3/identity/profile-mappings/create-and-confirm` additionally requires
  `household.manage`. It atomically creates a new Cloud Profile, its initial
  creator binding, the confirmed mapping, and an audit event. Only safe
  presentation/classification values are accepted.

Caller-supplied account, household, role, access, mapping, and profile-owner
fields do not authorize the action. `view` alone is intentionally insufficient
to confirm a mapping.

## iOS behavior

Profile Management exposes a separate Cloud Profile Mapping screen. It loads
Cloud mappings only after the app's already-established protected Cloud session
is available, validates persisted local `confirmed` mappings against that
server response, and leaves all local states intact when offline or the request
fails. It offers an explicit review sheet before either confirmation path.

`Local Only` and `Defer` are persistent device-local states. They issue no
Cloud request and create no Cloud record. `unresolved` signals that a previous
Cloud mapping needs a new explicit review; it does not alter local playback,
home, library, requests, or local profile behavior.

## Planning, audit, and rollback

`scripts/plan-local-profile-cloud-mapping.py --input <sanitized-fixture.json>`
is a fixture-only, zero-write classifier. It reports invalid opaque sources,
missing installation context, inactive membership, cross-household or existing
mapping conflicts, duplicate local sources, and candidates requiring explicit
confirmation. Its report hashes all supplied references and `--execute` is
intentionally rejected. It has no AWS client and must not be used as an
execution tool.

Audit events use the existing privacy-safe audit writer and never contain
local source values, names, secrets, tokens, PINs, DPoP proofs, or media data.
Rollback is a separate, authorized operation on newly created mapping rows
only. It must not modify legacy local profiles, history, settings, bindings,
or Cloud accounts.
