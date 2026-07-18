# Kaevo Security Remediation Plan

## Current disposition

The audit patches are local only. They must be reviewed, committed intentionally, deployed in dependency order, and reverified before they count as operational remediation.

## Phase 0 — Preserve and recover (before any security deployment)

**Target: immediately**

1. Snapshot/export the currently deployed Cloud configuration and DynamoDB tables.
2. Confirm immutable/offline backup for Jellyfin media and plugin configuration.
3. Record deployed iOS build, Cloud Lambda version, relay image digest, Home image digest, plugin version, and Jellyfin version.
4. Create rollback packages for Cloud, Home Server, and plugin. Do not use live media as a test fixture.
5. Retain the isolated Tdarr trial as **Coming Soon** with source deletion disabled.

Exit: rollback has been rehearsed without touching live media.

## Phase 1 — Ship the confirmed code fixes

**Target: 24–48 hours**

Deployment order:

1. Cloud conditional-state, tenant-pinning, privilege, parental-policy, and session fixes.
2. Playback Relay unchanged but redeploy only if its image provenance/digest is confirmed.
3. Home Server fail-closed auth, AES-GCM storage, protected reads, and timeouts.
4. Jellyfin Plugin authenticated-controller build through the established **GitHub release and Jellyfin catalog** path.
5. iOS build with Release development credentials compiled out.

Required checks:

- All test counts in the test matrix pass.
- Existing connector cannot change profile.
- Old session fails after refresh.
- Pairing/trial token succeeds once only.
- Child/profile bearer receives `403 owner_auth_required` for protected settings.
- Unauthenticated plugin/Home sensitive endpoints return 401/403.
- Release binary marker scan remains clean.
- Playback, PiP, audio selection, Remote Access, optimizer pause/cancel, and Family filtering pass on Jefferson's iPhone.

Exit: patches are deployed, regression results archived, and rollback remains available.

## Phase 2 — Deploy and prove the locally implemented production identity

**Target: before closed alpha**

1. Confirm the Cognito Essentials/Plus feature-plan cost, then deploy the V2 pre-token access-claim issuer and separate enrollment-only client/function only in a freshly derived isolated staging environment.
2. Enroll a synthetic owner through the atomic bootstrap, obtain a new main-client access token, and prove its six Kaevo claims match the four authoritative identity records. ID tokens must remain unusable for API authorization.
3. Drill `authz_version`, role, membership, disable, and revoke changes; each already-issued token must fail on the next protected request even though its cryptographic lifetime is 15 minutes.
4. Verify the implemented human roles `owner`, `adult`, and `child`; machine roles remain P-256/DPoP and support must not inherit household authority.
5. Prove implemented recent-auth enforcement for parental settings, connector/device changes, optimizer execution, provider mutation, and destructive work.
6. Migrate to implemented 15-minute DPoP-bound access tokens and rotating refresh families; retire every legacy portable session after a bounded grace window.
7. Add server-side owner approval for child dynamic-profile recommendations and actionable notifications.
8. Confirm the implemented production-empty development credential condition in the deployed CloudFormation stack; keep bypasses only in Debug and non-production environments.
9. Design and exercise adult invitation, child-login promotion, recovery/rebinding, passkey/MFA enrollment, device removal, and connector re-pairing end to end.

Exit: no protected production route relies on a shared secret; copied access/refresh/connector credentials fail from another key; revocation and recovery drills pass.

## Phase 3 — Detection, recovery, and abuse resistance

**Target: before TestFlight expansion**

1. Enable DynamoDB point-in-time recovery for settings, sessions, entitlements, connectors, devices, and remote requests.
2. Add bounded-retention structured audit logs for auth, pairing, token rotation/reuse, tenant mismatch, command approval, connector changes, and optimizer actions. Never log bearer/grant/provider secrets or filesystem paths.
3. Add API access logs with grant-bearing paths redacted/disabled and explicit Lambda/relay retention.
4. Add WAF/per-identity quotas for pairing, trials, avatar/image proxy, remote commands, and playback grants.
5. Alarm on tenant mismatch, repeated pairing failures, replay conditions, auth failures, command failure spikes, connector flapping, Lambda errors/throttles, relay saturation, and unexpected spend.
6. Produce SBOMs and enforce dependency, secret, IaC, SAST, and artifact-provenance checks in CI.
7. Sign plugin catalog/release metadata and verify with a pinned publisher key.

Exit: security events are detectable, attributable, retained, and recoverable.

## Phase 4 — Network and provider hardening

**Target: before public beta**

1. Implement provider URL policy: allowed schemes/ports, no userinfo, explicit denial of loopback/link-local/metadata/multicast/unspecified destinations, DNS resolution revalidation, redirect restrictions, bounded responses/timeouts.
2. Split the monolithic Lambda/IAM role by public onboarding, profile data, connector control, and playback functions.
3. Add optional Tailscale Private Direct mode with a generated least-privilege grants policy.
4. Review TrueNAS, router, Docker, GitHub, Apple Developer, AWS root/administrators, and secrets-manager controls with MFA and least privilege.
5. Pin production images by digest, run as non-root/read-only where possible, drop Linux capabilities, and define CPU/memory/PID limits.

Exit: home/provider/admin services are not accidentally reachable and a single component compromise has a constrained blast radius.

## Phase 5 — Independent assurance

**Target: before public App Store release**

1. External API/mobile/network penetration test including multi-tenant authorization, token theft/replay, pairing, SSRF, relay grants, and child-policy bypass.
2. Mobile binary/Keychain/jailbroken-device assessment against OWASP MASVS.
3. Chaos/restore exercise for Cloud tables, connector outage, relay outage, Jellyfin restart, and interrupted optimizer work.
4. One-title destructive optimizer canary against disposable media, with checksum, backup, rollback, metadata refresh, and playback verification.
5. Incident-response tabletop and customer notification/data-deletion procedures.

Exit: all Critical/High findings are closed or explicitly risk-accepted by the owner, and no release-blocking security test is red.

## Immediate owner decisions

- Approve the implemented Cognito design and decide whether passkeys are required or MFA is an allowed fallback.
- Decide whether parental-control sync remains disabled in Release until owner-scoped auth ships (recommended: **yes**).
- Approve backup/log-retention costs and WAF/monitoring budget.
- Choose whether Tailscale is an advanced optional mode (recommended) rather than the only remote-access path.
- Define the maximum tolerated media-loss scenario; recommended answer is zero originals without a separately verified backup.
