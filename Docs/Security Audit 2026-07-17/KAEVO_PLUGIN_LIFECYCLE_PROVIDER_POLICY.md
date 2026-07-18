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
- Remote playback remains disabled because the v2 lifecycle does not issue or reuse the retired portable playback-grant key.

## Provider destination policy

- One policy validates configuration and every provider request.
- Only HTTP(S), provider-specific ports, normalized IDN hosts, and explicit private destinations are eligible.
- User information, fragments, wildcard hosts, zone identifiers, alternate numeric forms, public addresses, loopback, link-local, multicast, unspecified, mapped prohibited addresses, and metadata-class destinations fail closed.
- Every DNS answer must be private and the complete sorted address set must match the administrator-approved set at request time. Any change requires reapproval.
- `SocketsHttpHandler.ConnectCallback` connects directly to a validated address while preserving the approved hostname for TLS SNI and certificate validation.
- Automatic redirects are disabled. Explicit redirects are limited, GET/HEAD-only, and must retain scheme, origin, approved base path, and validated destination set. HTTPS downgrade and origin escape fail.
- Credentials are attached only after configuration approval and can never cross an accepted redirect to a new origin.
- Responses and connection/DNS operations are bounded.
- Security-stage allows only exact mock-service names declared for the disposable isolated network; this is not a production default.
- Provider policy audit records contain provider type, outcome, security class, a truncated SHA-256 destination reference, and a generic reason. They contain no URL, host, IP, query, credential, or response body.

## Candidate validation

The canonical Plugin suite expanded from 79 to 114 passing tests. Cloud (130 passed, 3 accepted skips), Home Server (33), Playback Relay (20), and Media Optimizer (52) retain their accepted baselines. SAM validation, Bandit, Python dependency audits, NuGet audit, and the candidate-delta secret scan pass. Operational closure remains gated on the disposable Jellyfin and synthetic security-stage proof.
