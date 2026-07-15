
---

## Phase 2 — DynamoDB Event Capture

Date: 2026-07-07
AWS Region: us-west-2
Stack Name: kaevo-cloud-dev

## Added

- DynamoDB table: kaevo-cloud-dev-profile-events
- POST /v1/events now saves profile behavior events
- GET /v1/events/recent reads recent events for a profile
- Temporary dev API key protection added through x-kaevo-dev-key
- Events include 90-day TTL cleanup through expires_at

## Verified

Successfully saved and read event:

- profile_id: profile_123
- event_type: view_details
- item_id: movie_456
- device_type: tvos
- source: jellyfin

## Next Phase

Phase 3 should add POST /v1/events/batch so iOS/tvOS can upload multiple behavior events in one request.

---

## Phase 2 — DynamoDB Event Capture

Date: 2026-07-07
AWS Region: us-west-2
Stack Name: kaevo-cloud-dev

## Added

- DynamoDB table: kaevo-cloud-dev-profile-events
- POST /v1/events now saves profile behavior events
- GET /v1/events/recent reads recent events for a profile
- Temporary dev API key protection added through x-kaevo-dev-key
- Events include 90-day TTL cleanup through expires_at

## Verified

Successfully saved and read event:

- profile_id: profile_123
- event_type: view_details
- item_id: movie_456
- device_type: tvos
- source: jellyfin

## Next Phase

Phase 3 should add POST /v1/events/batch so iOS/tvOS can upload multiple behavior events in one request.

---

## Phase 4 — Profile Settings Sync

Date: 2026-07-07
AWS Region: us-west-2
Stack Name: kaevo-cloud-dev

## Added

- DynamoDB table: kaevo-cloud-dev-profile-settings
- GET /v1/profiles/{profileId}/settings
- PUT /v1/profiles/{profileId}/settings
- Default profile settings response
- Saved profile settings response
- Version updated to 0.0.4

## Verified

Successfully saved and read profile settings:

- profile_id: profile_123
- display_name: Jefferson
- preferred_home_layout: cinematic
- discovery_provider: automatic
- download_recovery_mode: notify_only

## Next Phase

Phase 5 should make /v1/provider-settings dynamic instead of static.
It should read/write provider settings using the existing profile settings table.

---

## Phase 4 — Profile Settings Sync

Date: 2026-07-07
AWS Region: us-west-2
Stack Name: kaevo-cloud-dev

## Added

- DynamoDB table: kaevo-cloud-dev-profile-settings
- GET /v1/profiles/{profileId}/settings
- PUT /v1/profiles/{profileId}/settings
- Default profile settings response
- Saved profile settings response
- Version updated to 0.0.4

## Verified

Successfully saved and read profile settings:

- profile_id: profile_123
- display_name: Jefferson
- preferred_home_layout: cinematic
- discovery_provider: automatic
- download_recovery_mode: notify_only

## Next Phase

Phase 5 should make /v1/provider-settings dynamic instead of static.
It should read/write provider settings using the existing profile settings table.

---

## Phase 5 — Provider Settings Sync

Date: 2026-07-07
AWS Region: us-west-2
Stack Name: kaevo-cloud-dev

## Added

- GET /v1/provider-settings?profile_id=profile_123
- PUT /v1/provider-settings?profile_id=profile_123
- Provider settings now read/write through the profile settings table
- Version updated to 0.0.5

## Verified

Successfully saved and read provider settings:

- discovery_provider: seerr
- request_provider: seerr
- download_recovery_provider: sonarr_radarr
- download_recovery_mode: notify_only

## Next Phase

Phase 6 should add device registration:

- POST /v1/devices/register
- GET /v1/devices?profile_id=profile_123

---

## Phase 6 — Device Registration

Date: 2026-07-07
AWS Region: us-west-2
Stack Name: kaevo-cloud-dev

## Added

- DynamoDB table: kaevo-cloud-dev-devices
- POST /v1/devices/register
- GET /v1/devices?profile_id=profile_123
- Version updated to 0.0.6

## Verified

Successfully registered and listed:

- Jefferson iPhone
- Living Room Apple TV

## Next Phase

Phase 7 should add Cognito/Auth foundation.

---

## Phase 7 — Cognito/Auth Foundation

Date: 2026-07-07
AWS Region: us-west-2
Stack Name: kaevo-cloud-dev

## Added

- Cognito User Pool
- Cognito User Pool App Client
- Cognito JWT issuer
- Test Cognito user
- Version updated to 0.0.7

## Verified

Successfully generated Cognito login tokens:

- TokenType: Bearer
- ExpiresIn: 3600
- IdToken generated
- AccessToken generated

## Current Auth State

Kaevo Cloud has Cognito ready, but API routes are still using the temporary x-kaevo-dev-key for testing.
This is intentional so iOS/tvOS integration remains easy during early development.

## Next Phase

Phase 8 should add entitlement/subscription status stubs.

---

## Phase 8 — Entitlements / RevenueCat Stub

Date: 2026-07-07
AWS Region: us-west-2
Stack Name: kaevo-cloud-dev

## Added

- DynamoDB table: kaevo-cloud-dev-entitlements
- GET /v1/entitlements?profile_id=profile_123
- PUT /v1/entitlements?profile_id=profile_123
- Version updated to 0.0.8

## Verified

Successfully saved and read entitlement state:

- plan: individual
- subscription_state: active
- cloud_enabled: true
- family_enabled: false
- product_id: kaevo_cloud_individual_monthly

## Next Phase

Phase 9 should make /v1/home/personalized return basic rows from saved events, settings, and entitlements.

---

## Phase 9 — Basic Personalized Home Rows

Date: 2026-07-07
AWS Region: us-west-2
Stack Name: kaevo-cloud-dev

## Added

- GET /v1/home/personalized?profile_id=profile_123 now returns real starter rows
- Personalized rows use recent events, profile settings, provider settings, and entitlements
- Version updated to 0.0.9

## Verified Rows

- Continue Watching
- Because Of Your Recent Activity
- Recent Searches
- Kaevo Cloud status

## Verified Data

- Continue Watching included movie_789 from play_started
- Recent Activity included movie_789 and movie_456
- Recent Searches included dexter
- Cloud Status showed individual plan, active subscription, Seerr provider settings

## Next Phase

Phase 10 should connect the iOS/tvOS dev app to Kaevo Cloud using the dev API URL and temporary x-kaevo-dev-key.
# Version 0.0.17 — Deployed

Date: 2026-07-14

- Added rate-limited plugin-confirmed Cloud trial activation.
- Added hashed, revocable, profile-bound app sessions.
- Added trial entitlement creation and expiry.
- Added app-session authorization for read-only metadata, artwork, settings,
  device, and status routes.
- Kept entitlements writes, remote commands, playback grants, and mutations out
  of app-session scope.
- API and relay tests: 15 passed.
- SAM validation and build: passed.
- Deployed successfully to the development stack.
- Live health reported `0.0.17`.
- Guarded session routes, existing app compatibility, and the existing online
  Jellyfin plugin connector passed after deployment.

# Version 0.0.19 — Deployed

Date: 2026-07-14

- Added profile-bound app-session refresh and existing-device rotation.
- Migrated the physical iPhone, then removed its retired credential.
- Removed the public migration route and legacy app credential from runtime.
- Verified the migrated session from a fresh physical-device app launch.
- API and relay tests: 16 passed.
- SAM validation and build: passed.
- Live health reported `0.0.19`.
