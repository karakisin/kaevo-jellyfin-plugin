# Kaevo Cloud

Kaevo Cloud provides optional remote access for Kaevo through the Kaevo
Jellyfin Plugin. It does not replace Jellyfin and does not require a separate
home-server application.

## Active architecture

1. The Kaevo app signs in to Jellyfin and confirms the Kaevo plugin.
2. The user chooses **Start Cloud Trial** in Kaevo.
3. Kaevo Cloud creates a short-lived plugin pairing request.
4. The Jellyfin plugin opens an authenticated outbound connection.
5. Kaevo displays **Remote Access Ready**.

Remote metadata and artwork are the first supported Cloud capabilities.
Remote playback and remote mutations remain separate later phases.

## Active source

- `api/src/handler.py` — live Cloud HTTP API (`0.0.19`)
- `api/tests/` — API security and contract tests
- `relay/kaevo_relay/` — experimental playback relay, not production-enabled
- `relay/tests/` — relay security tests
- `infra/template.yaml` — current development infrastructure template
- `scripts/` — active diagnostics and provider probes
- `docs/` — current architecture, contract, and status

Historical phase snapshots and retired standalone Home Connector tooling are
preserved under `archive/legacy-home-connector/`. They are not part of the
supported runtime.

## Safety boundaries

- Never store media files in Cloud.
- Never return local URLs, filesystem paths, or provider credentials to apps.
- Keep pairing codes short-lived and connector tokens hashed at rest.
- Keep trial activations short-lived and app session tokens hashed at rest.
- Bind every app session to one Cloud profile.
- Allow only bounded, explicitly approved plugin routes.
- Keep playback and mutations disabled until their dedicated validation phases.

## Local validation

```sh
python3 -m pytest api/tests relay/tests
```

Live tests require locally supplied development configuration. Secrets are
never committed.

## Release state

- Live development API: `0.0.19`
- Plugin-confirmed, revocable Cloud trial sessions are active.
- Existing devices migrate once, rotate their app session, and remove the
  retired shared app credential from Keychain.
- The public migration route and legacy app credential are disabled.
- Live health, guarded session routes, session refresh, and the existing
  plugin-backed connection passed after deployment.
