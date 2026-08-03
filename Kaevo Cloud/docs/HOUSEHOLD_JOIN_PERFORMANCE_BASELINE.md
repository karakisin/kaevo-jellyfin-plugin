# Household Join Performance Baseline

## Scope and evidence boundary

This is a development-only, read-only baseline recorded on 2026-07-28 before
Fixture B. It does not fabricate client-stage timings that were not captured.
Fixture A's retained protected manifest contains 155 journal events but no
stage-timing fields, so it is not a valid source for launch, callback, or Home
duration claims.

## Service baseline

CloudWatch's previous 24-hour Lambda duration sample contained 51 invocations:
467 ms average and 1,139 ms maximum. Five historical errors were found, but
each predates the currently deployed function revision (2026-07-28 10:04 UTC):
an old profile-table NameError, earlier IAM/configuration attempts, and an old
missing-PyJWT import. The deployed handler ZIP matches the reviewed source,
includes PyJWT, and resolves the corrected profile table. The post-deployment
window contained four invocations and zero errors.

The HTTP API uses the unqualified function integration; no alias or published
version was found that could select a different handler revision.

## Client-path static review

The identity-context refresh starts independent identity and mapping reads in
parallel at KaevoIdentityContextService.swift:399-403. The Cloud client
reuses its injected URLSession at KaevoCloudClient.swift:599. No source
evidence showed duplicate protected bootstrap/profile requests, a main-thread
cryptography path, or a separate DPoP-key load in the normal path.

The focused physical Debug suites passed 57/57 on 2026-07-28. They establish
correct retry and state transitions but do not constitute measured latency
telemetry.

## Optimization decision

No code change is warranted from this evidence. A speculative cache, retry, or
request-coalescing change could weaken the existing subject, installation, or
response-loss safeguards without proving a user-visible improvement. The
baseline is within a reasonable development normal-path service range; Fixture
B will capture the missing physical timings before any performance claim:

- launch to entry resolution;
- managed-login presentation and callback;
- authorization-code exchange, OIDC validation, and DPoP setup;
- authenticated bootstrap;
- Profile Setup and installation registration;
- Home transition.

This is a LOW residual measurement gap, not a launch blocker. Fixture B is
authorized to proceed without a speculative micro-optimization.
