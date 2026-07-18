# Kaevo Security Test Matrix

Legend: **PASS** verified this audit; **BLOCKED** requires production architecture/credentials; **MANUAL** owner-console or physical-device proof; **PLANNED** not yet implemented.

## Automated and build verification

| Area | Test | Expected | Result |
|---|---|---|---|
| Cloud | Full API suite | No failures | **PASS — 59** |
| Cloud | Authoritative roles/capabilities | Child/adult claim escalation and stale role version rejected | **PASS** |
| Cloud | Cognito V2 access-token claims | Six Kaevo claims come only from a consistent authoritative graph; ID/enrollment tokens receive none | **PASS locally; staged real-token proof MANUAL** |
| Cloud | Owner identity bootstrap | Server-generated five-record transaction is idempotent and concurrent replay converges on one owner | **PASS locally** through actual boto3 wire capture and DynamoDB Local; corrected staged real-token proof **MANUAL** |
| Cloud | KSEC-011A condition conflict | Five-record transaction remains atomic, returns a generic response, and leaks no DynamoDB detail | **PASS locally**; corrected staged conflict proof **MANUAL** |
| Cloud | Claim issuer denial/privacy | Missing, inconsistent, revoked, wrong-pool/client, unsupported event, and dependency outage fail closed; canaries absent from logs | **PASS locally** |
| Cloud | Sender-constrained session | Wrong installation key, wrong device, DPoP replay rejected | **PASS** |
| Cloud | Refresh rotation/reuse | Consumed refresh revokes its entire family | **PASS** |
| Cloud | Sensitive owner actions | Fresh owner proof required; cross-household target is opaque | **PASS** |
| Cloud | Production dev key | Configured shared key is still rejected | **PASS** |
| Cloud | Pairing exchange concurrency/replay | Only first atomic consume succeeds | **PASS** |
| Cloud | Trial activation replay | Second activation rejected | **PASS** |
| Cloud | Session refresh | Old bearer immediately rejected | **PASS** |
| Cloud | Cross-profile connector/device write | Existing tenant cannot be rebound | **PASS** |
| Cloud | Expired async-TTL request | Cannot be claimed | **PASS** |
| Cloud | Terminal result replay | Completed/failed result cannot be overwritten | **PASS** |
| Cloud | Profile command privilege | Profile bearer cannot submit mutation/destructive operations | **PASS** |
| Cloud | Parental-policy bypass | Profile bearer cannot change protected keys | **PASS** |
| Relay | Existing relay suite | Ticket/grant/connector/timeout constraints pass | **PASS — 20 baseline** |
| Home | Full Home Server suite | No failures | **PASS — 27** |
| Home | Connector installation identity | Stable P-256 key, mode 0600, DPoP-bound requests | **PASS** |
| Home | Missing/weak iOS token | Startup/mutations fail closed | **PASS** |
| Home | Credential encryption/tamper | AES-GCM decrypts; tampering rejected | **PASS** |
| Home | Sensitive GET without auth | 401/403 | **PASS** |
| Plugin | Full Docker test suite | No failures | **PASS — 79** |
| Plugin | Controller default auth | Authenticated Jellyfin user required | **PASS** |
| Plugin | Sensitive config auth | `RequiresElevation` retained | **PASS** |
| Sidecar | Full Swift suite | No failures | **PASS — 52** |
| Sidecar | Traversal/symlink/broad-root | Plan/execute blocked | **PASS** |
| Sidecar | Confirmation/backup/output conflict | Mutation blocked safely | **PASS** |
| iOS | Release device build | Build succeeds | **PASS** |
| iOS | Debug build for Jefferson's iPhone | Signed build succeeds | **PASS** |
| iOS | Release development-key markers | Absent from app binary | **PASS** |
| iOS | Full simulator suite | Clean release gate | **PASS**; all 35 prior failures triaged and resolved with documented evidence |
| iOS | Installation identity | Persisted P-256 key and valid RFC 9449-shaped DPoP | **PASS** |
| IaC | SAM lint | Valid template | **PASS** |
| Static | Bandit Cloud/Relay | No findings | **PASS** |
| Static | Bandit Home | No real finding | **PASS** — one `DELETE` confirmation false positive |
| Dependencies | Python/NuGet audit | No known vulnerable resolved package | **PASS** after raising Cloud cryptography to patched 48.x |
| Live | Jellyfin public version | Supported/security-current release | **PASS — 10.11.11 observed** |

## Authorization and tenant-isolation release gates

| Scenario | Required assertion | Status |
|---|---|---|
| Profile A reads/writes Profile B settings/avatar/events/devices | 401/403 without existence leak | Automated equivalents pass; expand endpoint-by-endpoint before alpha |
| Profile bearer calls owner/admin command | 401/403 | **PASS for current command contract** |
| Child session weakens parental policy | Denied; fresh authoritative owner required | **PASS locally; staged workflow MANUAL** |
| Connector A claims/completes Connector B request | 401/conditional failure | Existing contract plus new terminal tests pass; add concurrency load test |
| Device ID collision across households | Reject without overwrite | **PASS** |
| Pairing code brute force | Throttle/lockout/alert | **PLANNED** |
| Stolen access token from another device | Wrong DPoP key/device rejected | **PASS locally** |
| Reused refresh token | Entire token family revoked | **PASS locally** |
| Revoked connector/app session | Every protected route rejects immediately | **PASS for identity/connector contracts; staged route sweep MANUAL** |
| Connector pairing, rotation, recovery, revocation, and unpair | Immutable binding, monotonic versions, current-key-only access, atomic privacy-safe audit | **PASS in isolated AWS staging: 26/26; cleanup zero** |
| Development key in production | Deployment/build gate fails | **PASS by Release scan, code, IaC, and adversarial test; console drift MANUAL** |

## Network, relay, and SSRF gates

| Scenario | Expected | Status |
|---|---|---|
| Cloud cannot reach arbitrary home path/query | Typed/allowlisted route only | **PASS by source/tests** |
| Expired/wrong-device/wrong-item playback grant | Reject | Baseline relay tests pass; physical negative test planned |
| Grant replay after expiry | Reject | Baseline pass; distributed concurrency test planned |
| Link-local metadata provider URL | Reject before connection | **PLANNED** |
| DNS name changes from private provider to metadata IP | Re-resolve/reject | **PLANNED** |
| Provider redirect to forbidden host | Do not follow or revalidate | **PLANNED** |
| Remote image oversized/decompression abuse | Size/time/memory bounded | Source bounds exist; fuzz/load test planned |
| Relay URL/log capture | No bearer/grant in retained logs | **MANUAL/BLOCKED** infrastructure review |
| TLS certificate/protocol | Modern TLS; hostname validation | Cloud health HTTPS passes; full scanner planned |
| Tailscale Private Direct | Only gateway port reachable; app auth still required | **PLANNED** |

## Mobile/device gates

| Scenario | Expected | Status |
|---|---|---|
| App session/provider credentials at rest | This-device-only Keychain protection | **PASS by source** |
| Device locked after reboot | Sensitive material unavailable until first unlock | **PASS by configuration; MANUAL runtime proof planned** |
| Face/Touch ID cancellation | Fall back only to Kaevo PIN; no system passcode bypass | Existing product proof; repeat security regression manually |
| Debug subscription bypass in Release | No bypass path | **PASS by conditional-compilation review/build** |
| Logs/crash reports | No tokens, keys, provider URLs, paths, or media-sensitive payloads | Redactor exists; inject canary secrets and inspect Sentry/log archive before beta |
| Clipboard/screenshot/app switcher | Sensitive screens protected as designed | **MANUAL** |
| Jailbroken/instrumented device token theft | Copied token alone fails; installation is rapidly revocable | **PARTIAL** — DPoP/revoke pass; jailbreak/attestation assessment MANUAL |
| Physical playback/PiP/audio switching | No regression after security deployment | **MANUAL on Jefferson's iPhone** |

## Optimizer, filesystem, and Tdarr gates

| Scenario | Expected | Status |
|---|---|---|
| Analyze-only library scan | No media/metadata mutation | **PASS in tests; previously device-tested** |
| Path traversal/symlink escape | Reject | **PASS** |
| Broad `/`, `/mnt`, `/Volumes` root | Reject | **PASS** |
| Output/backup/source conflict | Reject before ffmpeg | **PASS** |
| Interrupted ffmpeg/Jellyfin restart | Original remains; partial output cleaned/recoverable | Unit tests pass; live disposable canary still required |
| Pause/cancel/queue reorder | No duplicate/stranded/destructive job | Product verification exists; security chaos test planned |
| Post-conversion codec/audio validation | Output matches Apple Direct Play plan and selected audio is audible | **MANUAL/BLOCKED** due prior no-audio cases |
| Metadata refresh after verified output | One canonical Jellyfin item, no stale duplicate | **MANUAL** |
| Tdarr isolated source-to-output test | No source deletion/replacement | Trial-only proof completed; **Coming Soon** remains correct |
| Tdarr live-library enablement | Requires separate backup, canary, approval, rollback | **BLOCKED intentionally** |

## Operational/console checklist

| Control | Owner verification |
|---|---|
| AWS root/admin MFA, no root keys | MANUAL |
| Cognito/OIDC production roles and MFA/passkeys | V2 claim issuer/bootstrap source PASS; Cognito tier/cost decision and staged enrollment/recovery MANUAL |
| DynamoDB PITR and restore drill | PLANNED |
| S3 public-access block/versioning/lifecycle | Source PASS; console drift MANUAL |
| CloudTrail, API/Lambda/relay audit retention and redaction | PLANNED |
| WAF, quotas, concurrency and billing alarms | PLANNED |
| GitHub MFA, branch protection, signed releases, Actions least privilege | MANUAL/PLANNED |
| Apple Developer/App Store Connect roles and MFA | MANUAL |
| TrueNAS/router no public admin/provider exposure | MANUAL |
| Docker containers non-root, dropped capabilities, read-only FS, resource limits | Partial; MANUAL |
| Secrets rotation and incident revocation runbook | PLANNED |

## Public-release security exit criteria

- Zero open Critical or High findings.
- Real owner/adult/child/device/connector identity and authorization.
- No shared development secret in deployed production systems or Release binaries.
- All tenant-isolation negative tests pass endpoint-by-endpoint.
- PITR/backup restore and incident revocation drills pass.
- Per-identity abuse limits and actionable alerts are enabled.
- External penetration test has no unresolved Critical/High result.
- Physical iPhone playback, PiP, audio switching, Family controls, Remote Access, and optimizer safety regression all pass on the exact release candidate.
