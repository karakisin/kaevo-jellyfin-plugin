# Kaevo Plugin lifecycle and provider-destination policy

## Scope

This candidate remediates KSEC-027 and KSEC-028 in the Kaevo Jellyfin Plugin without changing the completed KSEC-012A Cloud identity design.

## Connector lifecycle

- P-256 connector and separate recovery identities are generated locally.
- The environment-scoped `server_id`, connector ID, credential version, key references, thumbprints, lifecycle state, and pending transition are persisted in owner-only storage.
- Parent directories are mode `0700`; state and key files are mode `0600`.
- State replacement and key promotion use same-directory, flushed atomic replacement.
- Pairing calls the owner-authorized pairing-start route and only `/v2/home-connectors/pairing/exchange`.
- Connector requests use a fresh ES256 DPoP proof and `X-Kaevo-Credential-Version`; no connector bearer fallback exists.
- Rotation retains the accepted key until current-plus-proposed proof activation succeeds.
- Recovery uses the separate recovery key plus proposed replacement proof and recent owner authorization.
- Revocation and destructive unpair are exposed only through elevated Jellyfin routes with a required non-simple administrative action header.
- Existing legacy connector-token state is preserved until explicit owner reenrollment and otherwise fails closed as `lifecycle_upgrade_required`.
- Pending pair, rotation, and recovery state is reconciled after restart by proving the pending version against the existing connector heartbeat contract. A Cloud-accepted pending key is promoted atomically; when only the current key remains authoritative, the pending key is discarded. Neither branch permits a bearer fallback or version decrease.
- Lifecycle state carries an exact schema version. Unsupported future state fails closed without erasing keys or state.
- Remote playback remains disabled because the v2 lifecycle does not issue or reuse the retired portable playback-grant key.

## Provider destination policy

- One policy validates configuration and every provider request.
- Only HTTP(S), provider-specific ports, normalized IDN hosts, and explicit private destinations are eligible.
- User information, fragments, wildcard hosts, zone identifiers, alternate numeric forms, public addresses, loopback, link-local, multicast, unspecified, mapped prohibited addresses, and metadata-class destinations fail closed.
- Every DNS answer must be private and the complete sorted address set must match the administrator-approved set at request time. Any change requires reapproval.
- Multi-address connection selection uses the same deterministic sorted order as the approved address set.
- `SocketsHttpHandler.ConnectCallback` connects directly to a validated address while preserving the approved hostname for TLS SNI and certificate validation.
- Automatic redirects are disabled. Explicit redirects are limited, GET/HEAD-only, and must retain scheme, origin, approved base path, and validated destination set. HTTPS downgrade and origin escape fail.
- Encoded dot segments and encoded path separators are rejected before redirect dispatch.
- Credentials are attached only after configuration approval and can never cross an accepted redirect to a new origin.
- Responses and connection/DNS operations are bounded.
- Security-stage allows only exact mock-service names declared for the disposable isolated network; this is not a production default.
- Provider policy audit records contain provider type, outcome, security class, a truncated SHA-256 destination reference, and a generic reason. They contain no URL, host, IP, query, credential, or response body.

## Candidate validation

The canonical Plugin suite expanded from 79 to 126 passing tests. Continuation testing identified and remediated KSEC-029 (post-activation lifecycle crash reconciliation), KSEC-030 (order-dependent multi-address selection), KSEC-031 (encoded redirect traversal), and KSEC-032 (manifest/assembly version mismatch). Jellyfin package directories now fail closed when their declared version does not exactly match the loaded assembly version. Cloud (130 passed, 3 accepted skips), Home Server (33), Playback Relay (20), and Media Optimizer (52) retain their accepted baselines. SAM validation, Bandit, Python dependency audits, NuGet audit, and the candidate-delta secret scan must pass again before the continuation candidate is tagged. Operational closure remains gated on the disposable interruption, TLS, and update/rollback proofs.
