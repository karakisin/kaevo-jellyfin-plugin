# Kaevo Cloud Plan

## Goal

Offer optional, simple remote access through the installed Kaevo Jellyfin
Plugin while keeping normal family setup free of server terminology.

## C1 — Friction-free activation

- Present **Start Cloud Trial** in Kaevo iOS.
- Create a short-lived pairing request.
- Activate the local Kaevo plugin from the signed-in app.
- Show **Remote Access Ready** after the plugin is online.
- Hide URLs, IDs, tokens, and pairing codes from normal UI.

Status: working live in `0.0.19` with plugin-confirmed app sessions.

## C2 — Remote library

- Bounded metadata snapshots
- Artwork proxying with strict type and size limits
- Continue Watching metadata
- Cache and retry behavior for large libraries

Status: metadata and artwork are live; cache and image completeness continue
as client quality work.

## C3 — Production identity and billing

- Replace temporary development authentication with a profile-bound app
  session. Completed in `0.0.19`.
- Remove the one-time migration route and retired app credential. Completed.
- Activate, inspect, and revoke plugin-confirmed trial sessions. Implemented.
- Verify StoreKit transaction JWS values with Apple's App Store Server Library,
  bind the original transaction to the protected Kaevo Owner Session, and
  process signed App Store Server Notifications V2. Implemented locally; not
  deployed or configured in App Store Connect.

## Later approvals

- Remote playback through a dedicated secure relay
- Reversible Jellyfin user-data writes
- Additional providers

## App Store billing deployment gate

- Dependency floor: `app-store-server-library>=3.1.2,<4` so the verifier
  includes Apple's patched OCSP freshness behavior.
- Deployment input `AppStoreRootCertificatesBase64` must contain the current
  Apple PKI root certificates as comma-separated base64 DER. Missing or invalid
  roots fail closed with HTTP 503.
- Production notification path:
  `/v1/app-store-server-notifications/production`
- Sandbox notification path:
  `/v1/app-store-server-notifications/sandbox`
- Do not enter either URL in App Store Connect until the Cloud deployment has
  completed and Apple's signed TEST notification receives HTTP 200.
- No deployment or App Store Connect notification URL change was performed by
  this preparation pass.

## Non-goals

- No media storage in Cloud
- No separate Home Connector product
- No provider secrets in the app or Cloud responses
- No optimizer execution through Cloud
