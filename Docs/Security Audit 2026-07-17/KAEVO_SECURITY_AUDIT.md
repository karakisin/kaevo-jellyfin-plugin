# Kaevo Security Audit

**Audit date:** 2026-07-17
**Scope:** Kaevo iOS, Kaevo Cloud API and infrastructure, Playback Relay, Kaevo Home Server, Kaevo Jellyfin Plugin, Media Optimizer sidecar, Jellyfin/TrueNAS integration, update delivery, and the isolated Tdarr trial.
**Method:** adversarial source review, trust-boundary tracing, targeted negative tests, dependency and static scans, Release/Debug builds, and safe read-only live checks. No destructive live test was performed.

## Executive result

Kaevo is **not ready for a public multi-tenant release yet**. The deployed/pre-audit posture remains graded **C+**. The reviewed local candidate is **B**, contingent on deploying and operationally validating the identity/session migration described below. The two former architectural High blockers now have complete local code, infrastructure, and adversarial-test coverage; none of it is deployed by this audit.

Kaevo is safe enough for these stages:

| Stage | Result | Conditions |
|---|---|---|
| Jefferson's private development household | **Yes, with caution** | Keep Cloud in development mode, use the current trusted devices, keep destructive optimizer actions confirmation-gated, and deploy the security patches before relying on Remote Access. |
| Small closed alpha with trusted households | **Not yet** | Requires owner identity, role/scoped sessions, patched Cloud/Home/Plugin deployment, audit logs, backups, and incident controls. |
| TestFlight beta | **Not yet** | Release binary is clean, but Cognito provisioning, migration, revocation drills, and physical-device regression proof remain deployment gates. |
| Public App Store / multi-tenant service | **No** | Public identity, authorization, tenant isolation, monitoring, key rotation, abuse controls, and an external penetration test remain blockers. |

### Finding totals

| Severity | Confirmed | Patched locally | Open / operational blocker |
|---|---:|---:|---:|
| Critical | 0 | 0 | 0 |
| High | 11 | 11 | 0 code-open; 11 deployment-unverified |
| Medium | 10 | 5 | 5 |
| Low / informational | 5 | 0 | 5 |

The most important positive result is that Kaevo already has meaningful defense in depth: remote path/query allowlists, connector-bound playback grants, short grant lifetimes, encrypted/private S3 payload storage, Keychain storage, Debug-only subscription bypasses, typed optimizer commands, copy/backup verification, and confirmation gates around destructive work. These controls materially reduce the blast radius of several findings.

## Top five risks

1. **Production identity is not deployed.** The candidate now uses a Cognito JWT authorizer, authoritative principal records, explicit roles/capabilities, recent-auth checks, and production removal of the shared development credential. The currently deployed environment was not changed.
2. **Bound-session migration is not operationally proven.** The candidate uses 15-minute access tokens, rotating refresh families, RFC 9449 DPoP, installation P-256 keys, reuse detection, and revocation. Existing legacy sessions must be retired during deployment and physical-device recovery/revocation must be proven.
3. **Pre-fix app sessions crossed privilege boundaries.** A profile session could request mutation/destructive command families instead of being limited to playback and read-only inspection.
4. **Pre-fix local components trusted too much.** Home Server mutation auth could fail open when unconfigured, and Jellyfin Plugin controller metadata/status routes did not require a Jellyfin-authenticated user.
5. **Recovery and detection are underdeveloped.** Core DynamoDB tables lack declared point-in-time recovery, API access/audit logging is incomplete, and no WAF/abuse or security alerting policy is defined.

## Most likely serious breach route before these patches

The highest-impact practical chain was: obtain a reusable Kaevo app/development bearer from a compromised build or device; call Cloud command endpoints as the victim profile; enqueue a privileged Home/Plugin operation; let the outbound connector execute it inside the home network. Existing capability checks, exact identifiers, optimizer confirmation tokens, and plugin deletion gates made silent mass deletion harder, but did not justify granting profile sessions those functions. The patch now limits profile sessions to playback lifecycle, provider health, read-only optimizer inspection, and Sonarr episode inventory.

## Findings register

| ID | Severity | Component | Finding | State |
|---|---|---|---|---|
| KSEC-001 | High | Home Server | Missing iOS auth token caused mutation authentication to fail open; credential encryption used a reversible XOR scheme with a development default. | **Patched locally**: fail closed, minimum secret length, AES-GCM, legacy read migration. |
| KSEC-002 | High | Cloud commands | Profile sessions could authorize privileged mutation command families. | **Patched locally**: profile sessions limited to playback/read-only operations. Owner/admin path still required for mutations. |
| KSEC-003 | High | Connector pairing | Pairing code exchange was read-then-write and could be replayed concurrently. | **Patched locally** with a conditional atomic consume and regression test. |
| KSEC-004 | High | iOS Release | Release code could load a globally privileged development key from process configuration/legacy Keychain state. | **Patched locally** under `#if DEBUG`; Release removes legacy material. Release binary marker check passed. |
| KSEC-005 | High | Trial activation | One-time activation consumption was non-atomic. | **Patched locally** with conditional consume before session issuance. |
| KSEC-006 | High | Remote results | A connector could replay/overwrite terminal request completion or failure state. | **Patched locally** with `in_progress -> completing -> completed` conditional transitions. |
| KSEC-007 | High | Tenant isolation | Connector heartbeat/registration and device registration could rebind an existing identifier to another profile. | **Patched locally**: stored tenant is authoritative; cross-profile writes are rejected. |
| KSEC-008 | High | Jellyfin Plugin | Controller-level metadata/status routes lacked a default authenticated-user requirement. | **Patched locally** with class-level authorization; sensitive configuration remains elevation-gated. |
| KSEC-009 | High | Family controls | A profile session could rewrite cloud-synced `profile_type` and parental-control policy without owner proof. | **Patched locally** to fail closed for protected keys. Production owner-scoped auth is still required to restore this sync safely. |
| KSEC-010 | High | Cloud identity | Cognito was not integrated as an API authorizer; development-key authentication had no real owner/child/admin roles or recent-auth claims. | **Patched locally**: Cognito authorizer, owner/adult/child/device/connector/support roles, server-side capabilities, principal/tenant derivation, recent-auth enforcement, audit records, and production-empty development key. Deployment is unverified. |
| KSEC-010A | High | Cognito claim issuance | The candidate required Kaevo tenant/role/version claims but Cognito had no trusted issuance mechanism, so real identities failed closed. | **Patched in canonical source**: V2 access-token trigger, authoritative four-record graph, separate atomic enrollment, access-token-only schema, and request-time version checks. Staged real-token proof and Cognito tier/cost approval remain open. See `KAEVO_COGNITO_AUTHORITATIVE_CLAIMS.md`. |
| KSEC-011 | High | App sessions | Bearer sessions were profile scoped but portable across devices and valid for up to 30 days. | **Patched locally**: Secure Enclave/software P-256 installation key, RFC 9449 DPoP, 15-minute access tokens, rotating 30-day refresh families, reuse-family revocation, installation revoke, and this-device-only Keychain storage. Device attestation/risk scoring remains defense-in-depth follow-up. |
| KSEC-012 | Medium | App sessions | Rotation left the previous token active. | **Patched locally**: old session becomes rotated/revoked and immediately expires. |
| KSEC-013 | Medium | Queue | Expired queued requests could be claimed before asynchronous DynamoDB TTL deletion. | **Patched locally** with explicit expiry filtering and conditional claim. |
| KSEC-014 | Medium | Home Server | Provider inventory/audit and operation-status reads were unauthenticated. | **Patched locally**; only non-sensitive `/status` remains public. |
| KSEC-015 | Medium | Home relay | Jellyfin relay HTTP client had no bounded timeout. | **Patched locally** with connect/read/write/pool limits. |
| KSEC-016 | Medium | Workstation secrets | Ignored local Cloud credential files were mode `0644`. | **Fixed locally** to `0600`; contents were never printed or copied. |
| KSEC-017 | Medium | Cloud recovery | IaC does not declare DynamoDB point-in-time recovery, explicit API access logs, or bounded Lambda log retention. | **Open**; operational/cost decision required before deployment. |
| KSEC-018 | Medium | Provider provisioning | Elevated users can provision arbitrary LAN provider URLs; explicit link-local/metadata-address SSRF denial and DNS-rebinding protection are incomplete. | **Open**; private RFC1918 targets are legitimate, so validation must be purpose-built. |
| KSEC-019 | Medium | Updates | GitHub/catalog packages have checksums but no independent signed release metadata or pinned publisher trust root. | **Open**; add signing and verification before auto-update. |
| KSEC-020 | Medium | Relay privacy | Playback grants are transported in URL path components. They are short-lived and scoped, but can appear in intermediary/client logs. | **Open**; redact paths and disable access logging of grant-bearing URLs. |
| KSEC-021 | Medium | Abuse controls | API Gateway has baseline throttles, but expensive remote image, pairing, avatar, and remote-command flows lack per-identity quotas/WAF policy. | **Open**. |
| KSEC-022 | Low | Cloud IaC | Environment, resource names, function name, and API stage are hard-coded as `dev`, increasing promotion/configuration error risk. | Open. |
| KSEC-023 | Low | IAM | The monolithic Lambda has CRUD access to each application table and two buckets; compromise has a broad application-level blast radius. | Open; split roles/functions by responsibility. |
| KSEC-024 | Low | Home status | Public `/status` leaks basic service existence/version on the LAN. | Accepted for discovery; keep payload minimal. |
| KSEC-025 | Low | Dependency process | Vulnerability scans are manual and not enforced in CI with an SBOM/provenance gate. | Open. |
| KSEC-026 | Informational | Tdarr | The Tdarr lane is isolated and marked Coming Soon; it must not receive live-library deletion/replacement authority yet. | Correct current posture. |

## Validation evidence

### Local preservation commits

The reviewed implementation is preserved on the local `security/production-identity-hardening-2026-07-17` branches. It has not been pushed, published, or deployed:

- Cloud identity, authorization, and bound sessions: `6dfc771`
- Home Server and connector identity hardening: `6f6dd22`
- Jellyfin Plugin controller authorization: `f4d37cc`
- iOS audited baseline repair: `a0c9909` (iOS repository)
- iOS installation-bound sessions: `b7bebc1` (iOS repository)

- Cloud API: **59 tests passed**, including stolen-token/wrong-key denial, DPoP replay, refresh-family reuse, stale role version, recent-auth, opaque cross-household denial, provider/parental authorization, production development-key denial, production legacy-session/connector denial, device-bound playback grants, pairing replay, trial replay, tenant rebind, and terminal-state replay.
- Playback Relay: **20 tests passed** in the existing baseline; Bandit and dependency audit were clean.
- Home Server: **27 tests passed**, including fail-closed auth, AES-GCM tamper detection, protected reads, weak-configuration rejection, persistent mode-0600 connector keys, and request-bound connector DPoP.
- Jellyfin Plugin: **79 tests passed** in Docker after authorization regression tests were added.
- Optimizer sidecar: **52 tests passed**, including path escape, symlink escape, confirmation, backup/output conflict, cleanup, timeout, and unsupported stream tests.
- iOS: full simulator unit suite passed after all **35 formerly failing tests** were individually triaged; the evidence table is in `KAEVO_IOS_TEST_FAILURE_TRIAGE.md`. Release and Debug signed builds for **Jefferson's iPhone** passed. Installation proofs are decoded and verified in tests. Release-binary development-credential scan passed.
- IaC: `sam validate --lint` passed.
- Static scan: Bandit found no Cloud or Relay findings and one Home false positive where the literal `DELETE` is an intentional typed confirmation, not a password.
- Dependency scan: Home Python and Plugin NuGet scans reported no known vulnerable packages. Cloud scanning identified the former `<46` cryptography cap; the candidate now requires patched `cryptography>=48,<49` and the post-change audit is clean.
- Live read-only check: Jellyfin reports **10.11.11**, newer than Jellyfin's published [10.11.7 security-fix release](https://github.com/jellyfin/jellyfin/releases/tag/v10.11.7).

## Preserved patch-set classification

| Category | Findings | Files / behavior | Migration impact | Regression evidence |
|---|---|---|---|---|
| Cloud request and tenant safety | KSEC-002, 003, 005–007, 009, 012, 013 | `handler.py`, route contract tests; atomic one-time transitions, tenant pinning, terminal-state protection, restricted profile commands, protected policy writes | Existing records remain readable; deployment must preserve table keys/indexes | Cloud API suite and request-state/tenant adversarial tests |
| Production household identity | KSEC-010 | `security_identity.py`, `template.yaml`, sensitive-route tests; Cognito JWT claims are checked against principal records and a server capability matrix | New principal/audit tables and Cognito claims; staged owner/adult/child enrollment required | Claim escalation, recent-auth, stale-version, cross-household, provider/parental tests |
| Device-bound app sessions | KSEC-011, 012 | Cloud v2 installation/session routes plus iOS installation identity/config/client; P-256 DPoP, short access, rotating refresh family, revoke | New installation/session indexes; legacy sessions must be retired; owner must reauthenticate once per installation | Wrong-key, replay, reuse, wrong-device, Keychain/JWT-shape tests |
| Connector installation identity | KSEC-003, 007, 010 | Cloud pairing plus Home `connector_identity.py`/connector client; unique P-256 key, one-time atomic pairing, DPoP, revoke | Home generates a mode-0600 key and existing connectors require controlled re-pairing | Pair replay/rebind/revoke tests and Home connector identity tests |
| Home credential/auth hardening | KSEC-001, 014, 015 | Home auth, AES-GCM credential envelope, protected reads, bounded relay timeouts | Legacy credential envelope is read-only migration input; explicit secrets now required | Home 27-test suite including tamper and weak-config denial |
| Plugin authorization | KSEC-008 | Controller default `[Authorize]`; elevated provider configuration retained | Plugin update required through GitHub/catalog workflow | Plugin 79-test Docker suite |
| Release credential isolation | KSEC-004, 016 | iOS `#if DEBUG`, production-empty IaC dev key, local file mode 0600 | Debug environments retain explicit opt-in only | Release binary scan, production-key adversarial test, SAM lint |
| iOS baseline repair (separate, non-security) | Not a finding | Intentional model/test corrections documented line-by-line in `KAEVO_IOS_TEST_FAILURE_TRIAGE.md` | No identity migration impact | Full simulator suite passes; 35 original failures classified |

No unrelated media, UI, optimizer, or deployment change was discarded. The non-security iOS baseline corrections are intentionally isolated for their own commit and review. Protected-route inventory was rechecked across provider settings, parental policy, connector ownership, installation/device management, optimizer execution, media/download deletion, entitlement mutation, and remote-command dispatch; ordinary profile operations remain limited to browsing/playback and explicitly read-only inspection paths.

## Limits of this audit

- No production penetration test, fuzzing campaign, mobile binary instrumentation, jailbroken-device test, AWS account configuration review, or destructive optimizer test was performed.
- The Home Server was not reachable at its expected LAN port during the audit, so its patched runtime behavior was proven by tests rather than a deployed probe.
- Source controls and repository IaC were reviewed, but out-of-band AWS console changes, TrueNAS firewall rules, router exposure, GitHub account protections, and Apple developer-account settings require owner-console review.
- The fixes are committed only to local security branches and remain **unpushed and undeployed**. Deployed security does not improve until Jefferson reviews and ships them.
- Physical iPhone playback, PiP, audio switching, Family controls, Remote Access, and session recovery were not exercised in this non-deploying security pass. Signed builds are not runtime proof.
- Cognito users/claims, WebAuthn/MFA enrollment, production table migration, legacy-session retirement, connector re-pairing, and revocation drills require an owner-approved staged deployment.

## Standards used

The review maps most closely to [OWASP API Security Top 10 2023](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)—especially object/function authorization, authentication, resource consumption, SSRF, and unsafe API consumption—and [OWASP MASVS](https://mas.owasp.org/MASVS/) for mobile storage, authentication, network, platform, code, resilience, and privacy controls.
