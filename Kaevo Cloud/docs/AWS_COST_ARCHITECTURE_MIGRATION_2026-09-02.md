# Kaevo AWS Cost and Architecture Migration

Status: isolated development is routed to the low-cost relay; private plugin 0.3.24 is paired over protocol 2 and its control connector is online after physical manual-link acceptance. Reproducible development build 161 was produced from clean commits, installed on the isolated iPhone SE, and published to a dedicated private iOS repository. Requests and playback acceptance remain production gates. Production traffic and the legacy ECS/ALB relay have not been changed.

## Executive summary

This migration replaces the 250 ms connector claim loop with an authenticated API Gateway WebSocket push channel and replaces the fixed ECS/Fargate plus ALB relay with one AWS Lightsail Nano container behind CloudFront. The code, infrastructure, tests, deployment workflow, rollback behavior, and final production/decommission gates are source controlled.

The transport work is the explicitly approved exception under `KAEVO-LOCK-REQUESTS-DOWNLOADS-2026-08-09`. It changes command transport, recovery, compatibility throttling, and connector protocol versioning only. Profile ownership, household membership, profile binding, download semantics, request semantics, and Family Sync authority are not changed.

Production cutover is intentionally guarded by physical-playback attestations. Until both attestations are supplied, the current ECS/Fargate task, ALB, old CloudFront distribution, and signing secret remain available for rollback.

## Architecture

```text
Kaevo app
  |-- Cognito -> API Gateway HTTP API -> Lambda -> DynamoDB/S3/SQS
  |                                      |
  |                                      `-- opaque request ID
  |                                           -> DynamoDB stream
  |                                           -> notification Lambda
  |                                           -> API Gateway WebSocket
  |                                                    |
  |                                                    `-> authenticated plugin
  |
  `-- signed playback grant -> CloudFront (TLS, no cache)
                                 | private origin header + TLS
                                 v
                           Lightsail Nano relay
                                 | secure persistent WebSocket
                                 v
                           Kaevo Jellyfin Plugin -> local Jellyfin
```

Media never traverses API Gateway, Lambda, DynamoDB, S3, or SQS. The relay moves bytes in transit and does not persist Jellyfin media.

## Connector control design

- The plugin completes the existing signed connector challenge before requesting a 90-second one-time control ticket.
- The ticket is bound to connector, household, environment, expiration, nonce, and protocol version. DynamoDB conditional consumption prevents replay.
- `$connect` repeats current connector and household binding validation before recording a connection with TTL.
- The DynamoDB stream sends only the opaque request identifier to the exact connector/household connection.
- The plugin claims the exact request using the authenticated conditional claim path. Duplicate delivery therefore cannot duplicate execution.
- API Gateway `GoneException` removes stale connection records; `$disconnect` is also handled.
- Connected plugins issue no empty HTTP claim requests. WebSocket keepalive control frames and bounded reconnect backoff maintain the channel.
- Disconnected recovery runs once every 60–75 seconds with jitter and stops immediately after reconnect. The strict upper bound is 43,200 recovery requests per connector in a 30-day fully disconnected month, rather than approximately 10.4 million requests at 250 ms.
- Protocol v1 collection claims authenticate first, then receive `426 Upgrade Required`, minimum protocol 2, and `Retry-After: 60`. The legacy route has an API Gateway burst limit of 4 and rate limit of 1 request/second. Protocol v2 collection claims are accepted only when explicitly marked as recovery.

## Relay selection and security

Lightsail Container Service was selected because the relay requires no AWS API at runtime. The existing grant signing value and a separate generated origin-auth value are resolved by CloudFormation and injected into the immutable deployment; the container has no AWS access key, task role, or AWS SDK credential.

- Power/scale: Nano, one node, 0.25 shared vCPU and 512 MB RAM.
- Origin: the Lightsail-managed HTTPS endpoint; CloudFront uses TLS 1.2 and `https-only`.
- Protected relay HTTP and WebSocket paths require a constant-time check of `X-Kaevo-Origin-Auth` in addition to signed playback-grant and connector authorization.
- Direct protected-origin requests are rejected. `/health` is intentionally public and reveals only service, state, and version.
- Dynamic responses, playlists, grants, and media have a zero-TTL cache policy. Viewer authorization, range, query, and WebSocket negotiation headers are forwarded, excluding `Host`.
- The image uses an immutable Lightsail image version derived from an exact Git revision. Mutable `latest` is not used.
- CloudFormation change sets reject removal or replacement during canary deployment.

## Access, audit, and observability

- Routine deployment uses GitHub OIDC, STS temporary credentials, `KaevoDeploymentRole`, and a separate CloudFormation execution role. Root is not used after bootstrap verification.
- One multi-region management-event CloudTrail is logging to a versioned, encrypted, public-blocked bucket with log-file validation and a 400-day lifecycle. High-volume data events are not enabled.
- API Gateway has an account-level CloudWatch delivery role. Operational log groups use 30-day retention and application logs redact credentials, tickets, grants, payloads, and URLs.
- Sparse alarms cover WebSocket 4xx/5xx, notification errors/DLQ age, request throttling, relay health, CloudFront 5xx, and bandwidth.
- Forecast budgets exist at $20 and $30. The SNS topic currently has no email subscription because no notification address was explicitly approved.
- No AWS Organization, Control Tower, IAM Identity Center organization enrollment, promotional credit, or billing-plan setting was changed.

## Cost estimate

Current reported baseline before migration is approximately $70/month: about $35 ECS/ALB/public IPv4, $12 Container Insights, $14–$16 polling, and $6 Secrets Manager, plus small serverless/transfer charges.

Estimated steady beta baseline after physical acceptance and legacy decommission:

| Service | Estimated monthly baseline |
|---|---:|
| Lightsail Nano container, scale 1 | $7.00 |
| Secrets Manager, 16 required secrets including origin auth | $6.40 plus negligible calls |
| API Gateway HTTP/WebSocket, Lambda, DynamoDB, and SQS at current beta use | $0.50–$2.00 |
| CloudFront requests and current-use transfer | $0.50–$3.00 |
| CloudTrail S3, CloudWatch logs/alarms, and sparse monitor | $0.25–$1.00 |
| **Estimated total** | **$14.65–$19.40/month** |

The estimate excludes promotional credits and taxes. Media transfer remains variable. Lightsail includes 500 GB per container service each month; CloudFront and any transfer above included allowances are usage-dependent. Scale must remain one unless measured concurrency proves Nano inadequate.

No existing secret is eligible for deletion before production cutover because rollback references remain active. The old signing secret must be retained after decommission because the Lightsail deployment continues to use it. All other existing secrets require a separate reference audit before deletion.

## Validation evidence

Automated suites:

- WebSocket/control and compatibility: 37 tests.
- Relay security/media semantics: 32 tests.
- Full Jellyfin plugin suite: 312 tests.
- Focused iOS Pairing V3 suite: 26 tests, including manual entry through the signed-ticket parser and explicit expiry classification.
- SAM lint: security baseline, connector control, and Lightsail relay templates.
- Development cloud validation: encrypted on-demand connection table with TTL; source request stream active; invalid ticket rejected; invalid WebSocket rejected; legacy route resolves to the authenticated compatibility handler; unauthenticated legacy claim rejected.
- Relay cloud validation: Lightsail deployment `ACTIVE`; direct health 200; direct protected route 403; CloudFront health 200; CloudFront protected route reaches grant authentication and returns 401 for an invalid grant.

The suites cover ticket expiry/replay/binding isolation, duplicate notifications and claims, stale connections, disconnected recovery, zero polling while connected, compatibility enforcement, secret-free logs, grant rejection, HTTP range responses, HLS paths, WebSocket authentication, origin authentication, and graceful upstream failure. Simulated tests do not substitute for physical iPhone playback.

### Development physical-validation preparation

Preparation completed through GitHub OIDC using migration branch head `3a532ae`. The relevant successful runs are relay deployment `33696082724`, development connector-control deployment `33696460589`, security baseline `33697110350`, development routing/private plugin build `33697435328`, and the final read-only evidence snapshot `33698072484`.

- The green relay is `ACTIVE`, uses Lightsail `nano` power at scale one, returns 200 through both direct health and CloudFront health checks, rejects a direct protected request with 403, and rejects an invalid edge grant with 401.
- CloudFront redirects viewers to HTTPS, uses an `https-only` origin, and negotiates TLS 1.2 to the origin.
- The running relay exposes only the two expected runtime secret names and no permanent AWS credential environment names.
- Two actually deployed development Lambda functions containing `PLAYBACK_RELAY_PUBLIC_URL` were updated and verified against green. A SAM parameter-only change set was not executed because its preview included unrelated API integrations and a conditional permission replacement. The development stack parameter therefore remains intentionally unchanged; a future full development stack update can overwrite this temporary validation routing and must not run during the physical window.
- Production still points to the legacy relay. The legacy relay stack remains `UPDATE_COMPLETE`; no production cutover or decommission target ran.
- Detailed metrics are enabled for the exact request claim, control-ticket, legacy compatibility, and WebSocket routes. Structured access logging is active without authorization data.
- Root access keys are zero, root MFA is enabled, temporary bootstrap delete permissions are absent from `KaevoDeploymentRole`, and the 15-minute baseline log scan found zero sensitive-field matches.
- Baseline window `2026-09-02T23:50:53Z`–`2026-09-03T00:05:53Z`: all HTTP claim/control and WebSocket route counts were zero; WebSocket 4xx/5xx were zero; the green CloudFront distribution recorded 13 requests and 4,370 downloaded bytes from automated health/security checks.
- Private plugin canary: version `0.3.24.0`; target ABI `10.11.0.0`; 312/312 tests passed. It adds the copyable signed one-time pairing link and fail-closed recovery when stale relay enablement has no valid URL before authoritative registration. DLL SHA-256: `1d2da08690edbdae015f0b08121484e60c8908b7c90cc895bd07f36d5f27205b`. ZIP SHA-256: `32a487c3ca985da7b1f21cc124c82012f2c3dea4ba34d587b3d6ba295b8cde4c`; Jellyfin catalog MD5: `7528076a0bfdb7d4df5b43239ad400d3`.
- Signed iOS development build: Kaevo `4.3 (160)`, bundle `com.sumagang.kaevo`, Development backend/channel, Apple Development team profile valid through `2027-08-03`, app binary SHA-256 `776c9c587ab5bc617eb6f4edac08c6c681d0c54f16e5727475a55b79e7edb14f`. Deep strict signature verification passed. On `2026-09-02`, the exact build was installed on the paired physical iPhone SE running iOS 26.5, and the installed-app inventory reconfirmed version `4.3` and bundle version `160`. The app was not launched, and the primary iPhone 14 Pro Max was not used.
- Redacted evidence: `/Volumes/HomeLab/AppData/Kaevo Pairing V3/BuildArtifacts/AWSMigrationPhysicalValidation/evidence-33698072484/kaevo-physical-validation-evidence.txt`.
- Private plugin ZIP: `/Volumes/HomeLab/AppData/Kaevo Pairing V3/BuildArtifacts/AWSMigrationPhysicalValidation/private-plugin-repository/Kaevo.Plugin.KaevoForJellyfin-0.3.24.0.zip`.
- The older isolated-install plugin tar and superseded artifacts remain preserved for rollback; they must not replace the active 0.3.24 canary.
- Physical Owner fallback acceptance: on the designated iPhone SE running iOS 26.5, the UI test opened `Kaevo Home & Cloud`, selected `Use Pairing QR or Link`, opened `Enter Pairing Link`, submitted the signed one-time link, reviewed the matching isolated server, explicitly selected `Connect This Jellyfin Server`, observed `Jellyfin connected`, and completed with zero test failures. The primary iPhone 14 Pro Max was not used.
- Post-install isolated health: Jellyfin `10.11.11`, Kaevo `0.3.24`, Pairing V3 state `paired`, protocol `kaevo-pairing-v3`, reauthentication not required, connector state `online`, and a heartbeat present after the observed restart. Playback relay status was still `reconnecting` with zero connected channels, so playback acceptance is not claimed.
- Preserved signed app archive: `/Volumes/HomeLab/AppData/Kaevo Pairing V3/BuildArtifacts/AWSMigrationPhysicalValidation/Kaevo-4.3-160-Development.app.zip`, SHA-256 `61cb461f91d1f887e123fea83228abf1bd1c16257c17d99c0bb805dbc5e119ac`; extraction and deep signature re-verification passed.

### 2026-09-03 continuation and reproducibility checkpoint

- A fresh read-only OIDC snapshot run, GitHub Actions run `33792282548`, completed successfully from migration branch `72fdd7a`. All deployment, cutover, and decommission targets were skipped.
- Snapshot window `2026-09-03T18:28:36Z`–`2026-09-03T18:43:36Z`: the control, green relay, and legacy relay stacks were `UPDATE_COMPLETE`; green was `ACTIVE`, Lightsail `nano`, scale one; direct health returned 200, direct protected access returned 403, CloudFront health returned 200, and an invalid grant returned 401. Sensitive-log matches and permanent relay AWS credential names were zero.
- The development playback target remained green and the production playback target remained legacy. Green is CloudFront distribution `E20YVNV4X2YVRD` (`d1kflwvshnfrv7.cloudfront.net`) with an `https-only` Lightsail origin. Rollback remains CloudFront distribution `EYVBMBTXQMWO7` (`d2my6r0wbl8u0h.cloudfront.net`) with the preserved legacy ALB origin. Both distributions remained deployed and enabled.
- During the same 15-minute window, legacy collection claims, exact claims, control tickets, WebSocket connect/disconnect/ping/recover routes, and WebSocket 4xx/5xx each recorded zero requests. The green distribution recorded 88 requests and 32,712 downloaded bytes. This is a clean baseline, not the required five-minute connected-plugin zero-polling acceptance.
- A fresh read-only check of the isolated server confirmed `Kaevo Apple Review`, Jellyfin `10.11.11`, Kaevo plugin `0.3.24.0` active, and the configuration UI reporting `Kaevo App Connected`. This does not replace protected protocol/heartbeat evidence or physical Requests/playback acceptance.
- The exact five-file manual-link slice was isolated into clean iOS branch `migration/aws-cost-ios-repro-20260903` at local commit `bfc40f2` (`141` insertions, `25` deletions). `git diff --check` and the credential/path scan passed. A pre-existing clean-base compile defect was repaired in a separate one-line commit, `78314ac`, restoring the `KaevoLibraryBrowsingSession.scrollOffset` state already referenced by committed navigation code. No unrelated dirty iOS file was staged, overwritten, stashed, or discarded.
- The focused Pairing V3 test command used commit `78314ac`, Xcode 26.6, Debug configuration, build-number overrides `4.3 (161)`, and the designated no-retention iOS 26.5 simulator. All 28 focused tests passed with zero failures and zero skips, including manual entry through the signed-ticket parser and explicit ticket-expiry classification.
- Kaevo `4.3 (161)` was built and Apple Development-signed from clean commit `78314ac8093a35d70128854db3b29af9a6df97c8`. Deep strict signature verification passed; app binary SHA-256 is `1b6daf1323bad2e67b813d31d655db5f7579687d97936e92ee8dc353dae01a45`. The Debug compilation has no production environment flag and therefore resolves to the development configuration.
- The exact build was installed on the paired physical iPhone SE and the installed-app inventory reconfirmed bundle `com.sumagang.kaevo`, version `4.3`, and bundle version `161`. A post-install preflight launch occurred at `2026-09-03T19:03:17Z`; no user interaction or request followed, and the app was terminated before the Requests gate because source publication remains blocked. The primary iPhone 14 Pro Max was not used.
- Preserved build 161 archive: `/Volumes/HomeLab/AppData/Kaevo Pairing V3/BuildArtifacts/AWSMigrationPhysicalValidation/Kaevo-4.3-161-Development.app.zip`, SHA-256 `877b1d0714a9aaa8273606bd410d5575ead2da1a9d809ff8515fd0221317d171`; ZIP integrity and extracted deep signature verification passed.
- The authenticated GitHub owner was verified as `karakisin`; private repository `karakisin/Kaevo-iOS` was created without collaborators or visibility changes to any existing repository. Branch `migration/aws-cost-ios-repro-20260903` was pushed with matching local and remote HEAD `2bcdabe460199d1b68451fd93eccbfaf05526fc3`; required commits `bfc40f2` and `78314ac` are ancestors. No tags, compiled artifacts, or Build 161 archive were uploaded, and `kaevo-jellyfin-plugin` was not modified by this publication.
- Before the first push, the repository and all 217 reachable commits were scanned with Gitleaks 8.30.1 plus filename and signing-material checks. The only scanner alert was an explicitly marked example Jellyfin API-key placeholder in historical commit `1aca028`; it was not a credential. No AWS/GitHub token, private key, provisioning profile, signing certificate, app archive, or actual secret was found. Commit `2bcdabe` adds explicit ignore coverage for DerivedData/Xcode user state, builds/archives/apps/IPAs, signing material, environment/AWS credential files, local runner/browser state, and physical-validation evidence.
- Immediately before the first physical Requests step, the development control table contained exactly one active connector record at protocol 2. Its redacted heartbeat field was last updated at `2026-09-03T19:00:51Z` and its TTL remained current. The `2026-09-03T18:58:10Z`–`2026-09-03T19:03:10Z` API Gateway baseline recorded zero legacy collection claims, zero exact claims, and zero control-ticket requests; no remote request record had been created since `2026-09-03T19:03:00Z` as of `2026-09-03T19:04:33Z`.

Physical observations are recorded only after the operator reports or the session directly observes them:

| Group | Scope | Status | Evidence |
|---|---|---|---|
| 1 | Plugin 0.3.24 installation, isolated server identity, protocol 2 connection | Passed | The isolated server remained `Kaevo Apple Review` on Jellyfin 10.11.11; 0.3.24 installed and survived an observed restart; manual-link pairing completed on the physical iPhone SE; protected status reported `paired`, protocol 2, connector `online`, heartbeat present, and no reauthentication requirement |
| 2 | Five-minute idle, request delivery, exactly-once execution | Pending | Ready for isolated Requests/Download Details validation |
| 3 | Wi-Fi, Jellyfin/plugin restart, app background/foreground recovery | Pending | Blocked on Group 2 |
| 4 | Direct play, HLS/transcode, seek, pause/resume, long playback | Pending | Blocked on Group 3 |
| 5 | Relay restart, origin outage/recovery, optional concurrency, final secret scan | Pending | Blocked on Group 4 |

## Physical canary checklist

Use only the isolated Kaevo test household and rights-cleared media. Record app build, plugin version/commit, device, network, timestamps, and screenshots/log references.

1. Confirm the updated plugin reports connector protocol 2 and connects to the development WebSocket channel.
2. Leave Requests/Download Details idle for five minutes; confirm zero empty claim HTTP requests while the WebSocket remains connected.
3. Submit one request; confirm delivery is normally under one second and executes exactly once.
4. Disconnect/reconnect Wi-Fi, restart Jellyfin/plugin, and background/foreground the app; confirm bounded automatic reconnect and lost-notification recovery.
5. Through the green relay, play rights-cleared direct-play media, HLS/transcoded media, and a long item. Seek forward/back, pause/resume, and verify byte-range responses.
6. Repeat after relay redeployment/restart and with the Jellyfin origin temporarily unavailable; confirm graceful failure and recovery.
7. If the isolated server supports it, run three simultaneous streams and inspect relay CPU/memory, 5xx, bandwidth, and connection alarms.
8. Confirm the CloudFront URL works, direct protected-origin access is rejected, and no ticket, token, grant, media URL, title, household identifier, or secret appears in logs.

If any step fails, do not run a production target. Preserve redacted evidence, keep the legacy stack live, and fix/retest.

## Prepared production commands

The workflow uses temporary OIDC credentials and reviewed CloudFormation change sets. Run each command only after the preceding physical checkpoint is recorded. `gh run watch` must report success before continuing.

```bash
gh workflow run kaevo-aws-migration.yml --repo karakisin/kaevo-jellyfin-plugin --ref migration/aws-cost-architecture-20260902 -f target=control-production -f physical_validation=KAEVO-CANARY-PHYSICAL-PLAYBACK-PASSED
gh workflow run kaevo-aws-migration.yml --repo karakisin/kaevo-jellyfin-plugin --ref migration/aws-cost-architecture-20260902 -f target=playback-cutover-production -f physical_validation=KAEVO-CANARY-PHYSICAL-PLAYBACK-PASSED
```

After those succeed, repeat the physical checklist against production. If production playback fails, the old relay is still live: run the `playback-cutover-production` change-set logic with the preserved pre-migration `PlaybackRelayPublicUrl`, or cancel before decommission. The legacy route target is restored automatically if the production connector-control stack is deleted.

Only after production physical playback passes:

```bash
gh workflow run kaevo-aws-migration.yml --repo karakisin/kaevo-jellyfin-plugin --ref migration/aws-cost-architecture-20260902 -f target=decommission-legacy-relay -f physical_validation=KAEVO-PRODUCTION-PHYSICAL-PLAYBACK-PASSED
```

That guarded target deletes the legacy stack and therefore its ECS service/task definition, ALB/listener/target group, old CloudFront distribution, security groups, public IPv4 use, Container Insights cluster, old monitor, and related roles. It explicitly retains `RelaySigningSecret`, because the new relay still references it.

## Rollback artifacts

- Baseline tag: `kaevo-aws-migration-baseline-20260902` at `7b3c02ac6057a153aa300df34a3eee636f31bc1c`.
- Redacted infrastructure snapshot: `/Volumes/HomeLab/AppData/Kaevo Pairing V3/Migration Baselines/20260902-pre-migration`.
- The snapshot records the old stack definition, outputs, CloudFront configuration, ECS task/service, ALB/listener/target group, image digest, API routes/stages, Lambda metadata, DynamoDB definitions, environment variable names, and secret ARNs without values.
- Before legacy decommission, rollback is immediate by restoring the production API stack's prior `PlaybackRelayPublicUrl`; no media or user data migration is involved.
- After decommission, redeploy the preserved `playback-relay.yaml` at the baseline tag with the recorded immutable image and retained signing secret, then restore the prior relay URL.

No secret value, permanent AWS credential, playback grant, private user data, or unredacted account identifier is included in this document or the baseline exports.

## Migration-owned source files

The migration changes below are measured from commit `34b15dc`, which preserved Jefferson's pre-existing dirty source snapshot. Those earlier user changes are not attributed to this migration.

- `.github/workflows/kaevo-aws-migration.yml`
- `Docs/REQUESTS_DOWNLOADS_FEATURE_LOCK.md`
- `Kaevo Cloud/api/Makefile`
- `Kaevo Cloud/api/connector_control/connector_control_handler.py`
- `Kaevo Cloud/api/tests/test_v3_connector_control.py`
- `Kaevo Cloud/api/tests/test_websocket_control.py`
- `Kaevo Cloud/api/websocket_control/__init__.py`
- `Kaevo Cloud/api/websocket_control/common.py`
- `Kaevo Cloud/api/websocket_control/notification_handler.py`
- `Kaevo Cloud/api/websocket_control/socket_handler.py`
- `Kaevo Cloud/api/websocket_control/ticket_handler.py`
- `Kaevo Cloud/docs/AWS_COST_ARCHITECTURE_MIGRATION_2026-09-02.md`
- `Kaevo Cloud/infra/connector-control.yaml`
- `Kaevo Cloud/infra/playback-relay-lightsail-canary.yaml`
- `Kaevo Cloud/infra/security-baseline.yaml`
- `Kaevo Cloud/infra/template.yaml`
- `Kaevo Cloud/relay/kaevo_relay/app.py`
- `Kaevo Cloud/relay/pyproject.toml`
- `Kaevo Cloud/relay/tests/test_relay_security.py`
- `Kaevo Cloud/relay/uv.lock`
- `Kaevo Cloud/scripts/build-connector-control-artifact.sh`
- `Kaevo Cloud/scripts/collect-aws-physical-validation-evidence.sh`
- `Kaevo Jellyfin Plugin/docs/PAIRING_V3_PLUGIN.md`
- `Kaevo Jellyfin Plugin/scripts/package-plugin.sh`
- `Kaevo Jellyfin Plugin/src/Kaevo.Plugin.KaevoForJellyfin/Api/KaevoController.cs`
- `Kaevo Jellyfin Plugin/src/Kaevo.Plugin.KaevoForJellyfin/Configuration/configPage.html`
- `Kaevo Jellyfin Plugin/src/Kaevo.Plugin.KaevoForJellyfin/Kaevo.Plugin.KaevoForJellyfin.csproj`
- `Kaevo Jellyfin Plugin/src/Kaevo.Plugin.KaevoForJellyfin/Models/KaevoModels.cs`
- `Kaevo Jellyfin Plugin/src/Kaevo.Plugin.KaevoForJellyfin/Services/KaevoCloudConnectorService.cs`
- `Kaevo Jellyfin Plugin/src/Kaevo.Plugin.KaevoForJellyfin/Services/KaevoCloudContracts.cs`
- `Kaevo Jellyfin Plugin/tests/Kaevo.Plugin.KaevoForJellyfin.Tests/ControlTransportContractTests.cs`
- `Kaevo Jellyfin Plugin/tests/Kaevo.Plugin.KaevoForJellyfin.Tests/PluginConfigurationPageTests.cs`

## AWS resource inventory

Created in `kaevo-security-baseline`:

- GitHub OIDC provider, `KaevoDeploymentRole`, and `KaevoCloudFormationExecutionRole`.
- API Gateway account log-delivery role and account association.
- Kaevo cost SNS topic/policy and $20/$30 forecast budgets. The conditional email subscription was not created.
- Encrypted/versioned/public-blocked CloudTrail bucket and bucket policy.
- One multi-region management-event CloudTrail with validation enabled.

Created in `kaevo-cloud-dev-connector-control`:

- Encrypted on-demand connections table with TTL.
- WebSocket API, development stage, 30-day access log group, `$connect`, `$disconnect`, `ping`, and `recover` routes/integrations.
- Ticket and exact-claim HTTP routes/integration; ticket Lambda/role/log group/permission.
- Socket Lambda/role/log group/permission.
- Request-stream notification Lambda/role/log group/event-source mapping and encrypted SQS DLQ.
- Configuration Lambda/role/log group/custom resource.
- SNS alert topic and alarms for WebSocket 4xx/5xx, notification errors, DLQ count/age, and legacy request throttling.

Created in `kaevo-playback-relay-green`:

- One Lightsail Nano container service with an immutable relay image deployment.
- Origin-auth secret, zero-TTL cache policy, origin-request policy, and CloudFront distribution.
- SNS alert topic, 30-day monitor log group, monitor Lambda/role/schedule/permission, relay health alarm, CloudFront 5xx alarm, and bandwidth-growth alarm.

Modified existing development resources:

- Enabled `NEW_IMAGE` DynamoDB stream on `kaevo-cloud-dev-remote-requests`.
- Applied bounded API Gateway stage throttles to the legacy collection claim, ticket, and exact-claim routes.
- Changed the legacy development claim route target to the authenticated protocol-compatibility handler. Stack deletion restores the recorded original target.

Deleted during failed-bootstrap recovery:

- One empty retained relay-monitor log group and one unused origin-auth secret from a rolled-back first create. Both were recreated under the successful stack.
- Temporary connector and relay failed-bootstrap delete permissions were removed after recovery.

No production application resource, ECS task, ALB, listener, target group, security group, public IPv4 resource, existing secret, existing CloudFront distribution, or user-data resource has been deleted. Those removals are intentionally deferred until production physical playback passes.
