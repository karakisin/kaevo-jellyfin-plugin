# Kaevo managed login and social sign-in

## Current dev contract

- Cognito managed login version 2 is the only browser authentication surface.
- Kaevo's native callback remains `kaevo://oauth/callback` with authorization-code PKCE.
- Google and Sign in with Apple are enabled in `kaevo-cloud-dev`; other environments remain disabled unless their Secrets Manager ARN parameters are non-empty.
- The identity-claim issuer independently verifies the exact enabled-provider allowlist.
- Provider credentials are resolved from Secrets Manager and are never exposed to the iOS app, Lambda environment variables, CloudFormation outputs, or Git.
- The four `/v2/identity/social-links` routes terminate at a dedicated dispatcher Lambda whose only permission is invoking the exact existing API Lambda. The dispatcher has no provider-secret access and does not log or transform request or response bodies.

## Kaevo branding

The managed-login style uses Kaevo graphite surfaces, champagne-gold controls and links, light text, rounded forms, and rounded buttons. Cognito owns the authentication form semantics and security behavior; Kaevo changes only the supported visual settings.

The dev user pool also has the managed custom domain `auth.kaevo.watch`. Its
ACM certificate is held in `us-east-1`, while the Cognito user pool remains in
`us-west-2`. The original Cognito prefix domain remains available during the
dev migration and must not be removed until every native build and every
external identity provider has been validated against the custom domain.

## Provider prerequisites

Each provider must allow two distinct callbacks:

- Cognito managed-login callback for a new social account:

  ```text
  https://<cognito-domain>/oauth2/idpresponse
  ```

- Kaevo's direct, explicit existing-account link callback:

  ```text
  https://api.kaevo.watch/v2/identity/social-links/callback
  ```

During the dev custom-domain migration, retain the existing Cognito callback
and the previous API Gateway callback for bounded rollback. Add both exact
first-party callbacks before switching clients:

```text
https://auth.kaevo.watch/oauth2/idpresponse
https://api.kaevo.watch/v2/identity/social-links/callback
```

The direct callback never receives the Kaevo owner token. It finishes only a
short-lived provider OAuth transaction whose state is stored as a one-way hash.

Google requires a web OAuth client with both callback URLs registered as exact
authorized redirect URIs.

Store a JSON secret with these keys:

```json
{
  "client_id": "<google web client id>",
  "client_secret": "<google web client secret>"
}
```

Sign in with Apple requires a Services ID, Team ID, Key ID, and Sign in with
Apple private key. Register both callback URLs as exact return URLs for the
Services ID. Store a JSON secret with these keys:

```json
{
  "client_id": "<apple services id>",
  "team_id": "<apple team id>",
  "key_id": "<apple key id>",
  "private_key": "<apple p8 private key>"
}
```

Do not place either JSON document in a parameter file or shell history. Create each secret through an interactive credential-safe workflow and pass only its ARN to CloudFormation.

## Existing-account safety gate

Cognito creates a separate federated profile at first social sign-in unless
that provider identity is linked to the existing local profile first. Kaevo's
linking transaction therefore:

1. begins from an existing DPoP-bound Owner Session Protected session;
2. requires an explicit confirmation in Kaevo before any provider request;
3. creates a five-minute, single-attempt OAuth state and nonce;
4. stores only the state hash in the existing app-sessions table;
5. requires a fresh provider authentication;
6. verifies the provider signature, issuer, audience, nonce, and timestamps;
7. uses the stable provider `sub` as the sole link authority;
8. requires a verified email when the provider supplies an email, but never
   uses email to choose or merge an account;
9. commits a privacy-safe audit reference before the Cognito link mutation;
10. links with `ProviderAttributeName=Cognito_Subject`, reads back the result,
    and never blindly retries an ambiguous mutation.

The isolated Cognito pre-sign-up guard prevents a provider login from creating
a duplicate federated profile when a verified email already belongs to an
existing account. It blocks the sign-up and directs the owner to use the
explicit link flow; it never performs an email-based link.

Provider ARN parameters and `SocialIdentityLinkCallbackUrl` must remain empty
in any environment whose focused tests, provider callback registrations,
reviewed change set, and rollback plan have not passed. The dev environment
completed those gates on 2026-07-22. Production remains disabled pending its
own independent review and authorization.

## Privacy and failure behavior

- Provider client secrets and the Apple private key remain only in Secrets
  Manager and the API Lambda's memory.
- The iOS app receives a short-lived authorization URL but never provider
  tokens or provider credentials.
- The provider OAuth code and identity token are not returned to iOS, logged,
  or stored after the callback.
- The app callback is only `kaevo://oauth/social-link?state=linked|failed`.
- Exceptions and provider response bodies are not logged or returned.
- A failed or expired transaction requires a new explicit attempt and cannot
  move, merge, or unlink an identity.

## Custom Kaevo sign-in hostname

Removing `amazoncognito.com` requires a Cognito custom domain. The deployment needs:

- a domain Kaevo owns, such as a chosen `auth` subdomain;
- a public ACM certificate for that hostname in `us-east-1`;
- a DNS alias to the CloudFront target Cognito creates;
- updated Google and Apple redirect/return URLs;
- an updated iOS authorization and token endpoint configuration;
- an overlap and rollback plan for the existing Cognito prefix domain.

The custom-domain migration is intentionally separate from provider enablement and from this branding-only change.

## First-party API hostname

The normal dev app and explicit social-link flow use `https://api.kaevo.watch`.
It is a regional API Gateway custom domain mapped at the empty base path to the
existing `dev` HTTP API stage. No route, authorizer, integration, or request
shape changes as part of this hostname migration.

The ACM certificate for `api.kaevo.watch` is held in `us-west-2`, matching the
regional API. GoDaddy DNS points `api.kaevo.watch` to the regional API Gateway
domain returned by CloudFormation. The generated `execute-api` hostname remains
available only as a bounded rollback endpoint and must not appear in normal
iOS configuration or in new provider consent screens.
