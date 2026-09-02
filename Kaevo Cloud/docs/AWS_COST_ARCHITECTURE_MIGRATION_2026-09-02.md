# Kaevo AWS Cost and Architecture Migration

Status: development control plane deployed; low-cost relay canary deployment and physical playback acceptance remain gates. Production traffic and the legacy ECS/ALB relay have not been changed.

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
- Relay security/media semantics: 31 tests.
- Full Jellyfin plugin suite: 305 tests.
- SAM lint: security baseline, connector control, and Lightsail relay templates.
- Development cloud validation: encrypted on-demand connection table with TTL; source request stream active; invalid ticket rejected; invalid WebSocket rejected; legacy route resolves to the authenticated compatibility handler; unauthenticated legacy claim rejected.

The suites cover ticket expiry/replay/binding isolation, duplicate notifications and claims, stale connections, disconnected recovery, zero polling while connected, compatibility enforcement, secret-free logs, grant rejection, HTTP range responses, HLS paths, WebSocket authentication, origin authentication, and graceful upstream failure. Simulated tests do not substitute for physical iPhone playback.

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
