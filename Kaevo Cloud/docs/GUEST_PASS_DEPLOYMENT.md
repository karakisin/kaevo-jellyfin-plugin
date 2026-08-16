# Guest Pass development deployment

Guest Pass is split from the legacy `kaevo-cloud-dev` stack so a deployment
cannot remove newer identity resources or refresh unrelated Cognito provider
secrets. Do not deploy the repository's full SAM template over that live stack.

## Managed resources

- `kaevo-guest-pass-storage-dev` owns the retained, encrypted
  `kaevo-cloud-dev-guest-passes` table through
  `infra/guest-pass-storage-dev.json`.
- `kaevo-guest-pass-dev` owns the eight HTTP API routes, Lambda invocation
  permission, API integration, and managed DynamoDB policy through
  `infra/guest-pass-dev.json`.
- The managed policy is intentional. The legacy API role has reached AWS's
  aggregate 10 KB inline-policy limit.

Both templates must produce Add-only change sets on first deployment. The
storage table requires SSE, point-in-time recovery, the `expires_at` TTL, and
the `household_id-created_at_epoch-index`. Reject any replacement, removal, or
unrelated modification.

## Runtime artifact

Build the API Lambda from a clean, immutable commit. Upload it to a versioned
S3 object, add `GUEST_PASSES_TABLE=kaevo-cloud-dev-guest-passes` without
changing any other environment value, and update code/configuration with the
current Lambda `RevisionId`. Never print or write the existing environment
map because it contains sensitive values.

The API and relay deployments are separate evidence gates. The relay image
must use a new tag and digest, pass the relay security suite, and reach ECS
steady state before the public health endpoint is accepted.

The Jellyfin plugin remains a manual operator update. Publish its verified
GitHub release, but do not install it or restart Jellyfin from this workflow.
