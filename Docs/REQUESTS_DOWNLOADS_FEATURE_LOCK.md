# Requests and Download Details service contract lock

- Lock ID: `KAEVO-LOCK-REQUESTS-DOWNLOADS-2026-08-09`
- Status: **LOCKED**
- Owner and physical approver: Jefferson Sumagang
- Client baseline: Kaevo 4.2 (122), physically exercised and confirmed by Jefferson on 2026-08-09 Pacific time.
- Plugin baseline: Jellyfin plugin 0.2.88. A committed or tagged artifact is not, by itself, proof of deployment or installation.

## Approval gate

No person or agent may alter the locked contract, its Cloud/connector/plugin implementation, its tests or packaging, or this lock without Jefferson's explicit manual and physical approval for the exact proposed change in the current task.

The approval must identify this lock or unmistakably identify the locked Requests/Download Details behavior and state that Jefferson manually and physically approves the proposed change. Standing permission, a previous approval, a broad instruction to proceed, automated tests, diagnostics, apparent urgency, deployment state, or an agent-authored approval record do not count. If that approval is absent, stop before editing and ask Jefferson.

Unlocking, narrowing, rebaselining, bypassing, deleting, or weakening this document requires the same approval. Approval for one change does not approve later changes.

## Approved migration exception — 2026-09-02

Jefferson Sumagang explicitly and physically approved the exact connector-transport change under this lock in the current AWS cost-migration task. That one approval authorizes only:

- replacing the 250 ms collection-claim loop with signed, short-lived, one-time WebSocket tickets and opaque push notifications;
- adding connector-control protocol v2, exact request-ID claims, bounded keepalive/reconnect behavior, and a disconnected recovery claim no faster than 60 seconds plus jitter;
- authenticating legacy callers before returning the minimum-version/upgrade response and tightly throttling the legacy collection route; and
- the directly corresponding Cloud, plugin, infrastructure, packaging, and contract-test changes.

This exception does not authorize changing request creation, connector ownership, household/profile authority, command semantics, exact provider bindings, conditional state transitions, completion/failure behavior, or the independent Profiles and Family Sync lock. This lock remains **LOCKED** for every other change, and this exception is consumed by the current migration.

## Locked service contract

The approved baseline includes:

- canonical immutable Cloud, household, profile, queue, request, Arr, Seerr, downloader, and provider IDs; no identity or authority inference from names or avatars;
- protected native owner/profile sessions, DPoP, connector signatures and diagnostics, fail-closed authorization, and separation between protected app requests and connector claim/complete/fail callbacks;
- exact profile-scoped and owner-scoped Seerr/request projection, including canonical self `seerr_user_id` attribution;
- exact downloader job control, command normalization, priority/state handling, authenticated connector claims, and provider read-back before a command is reported as successful;
- Cloud-authoritative queue telemetry and download state used by the iOS Requests dashboard and Download Details surface;
- compatible `/v1/remote-requests` protected app behavior and `/v3/remote-requests` connector behavior without weakening either authorization boundary;
- diagnostic and deployment-package builders used to reproduce the hardened Cloud functions.

Profile Switching and Who's Watching remain separate permission systems. Family Sync remains Cloud-authoritative; local state is only responsive/offline fallback.

## Protected service surface

The lock applies to behavior in these areas and to any replacement or new code serving the same contract:

- `Kaevo Cloud/api/connector_control/connector_control_handler.py`
- `Kaevo Cloud/api/src/handler.py`
- `Kaevo Cloud/api/src/pairing_v3.py`
- Requests, connector-control, remote-command, protected-identity, pairing, and diagnostic contract tests under `Kaevo Cloud/api/tests/`
- Requests/download-control and diagnostic package builders under `Kaevo Cloud/scripts/`
- corresponding remote-request claim, complete, fail, authorization, queue telemetry, and exact downloader-control behavior in `Kaevo Jellyfin Plugin/`;
- Jellyfin plugin release baseline 0.2.88 for this contract.

## Allowed without unlocking

Read-only review, diagnostics, diff inspection, and non-mutating tests are allowed. Unrelated service/plugin work may proceed only when it does not alter the locked contract or protected implementation. When scope is ambiguous, treat it as locked and ask Jefferson first.

This is an auditable repository and agent-process lock. It does not claim operating-system, Git-server, or cryptographic write prevention.
