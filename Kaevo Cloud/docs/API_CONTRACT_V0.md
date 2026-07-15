# Kaevo Cloud API Contract

Current live release: `0.0.19`

## Public service

- `GET /health`
- `POST /v1/trials/start` — rate-limited short-lived activation
- `POST /v1/trials/activate` — requires plugin confirmation

## Session routes

- `GET /v1/app-sessions/status`
- `POST /v1/app-sessions/refresh`
- `POST /v1/app-sessions/revoke`

App session tokens are returned once, stored only as hashes by Cloud, expire
with the trial, and are bound to one profile.

## App-authenticated routes

- Profile settings and entitlements
- Device registration
- Personalization events and home rows
- Plugin pairing start and status
- Remote route discovery
- Bounded remote metadata requests
- Bounded remote artwork requests

Version `0.0.19` accepts the profile-bound app session for normal app routes.
The one-time migration route is removed and the retired app credential is no
longer accepted.

## Plugin-authenticated routes

- Pairing exchange
- Plugin registration and heartbeat
- Remote-request claim, completion, and failure
- Short-lived relay-ticket creation

Plugin credentials are returned once during pairing and stored as hashes by
Cloud. Pairing codes expire after ten minutes.

## Safety rules

- Reject unpaired, expired, revoked, or incorrectly authenticated plugins.
- Allowlist provider, path, query, operation, and response size.
- Never expose provider secrets, local URLs, or filesystem paths.
- Metadata and artwork are read-only in the current supported phase.
- Playback grants are short-lived and do not enable playback by default.
- Remote mutations require a separate approved phase.
- App sessions cannot change entitlements, issue playback grants, create
  remote commands, or cross profile boundaries.

`api/src/handler.py` is the authoritative executable contract. Contract tests
live in `api/tests/`.
