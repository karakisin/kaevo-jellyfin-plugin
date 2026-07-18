# Kaevo Remote Access vs. Tailscale

## Bottom line

Tailscale would materially reduce Kaevo's public home-service attack surface, but it does **not** replace application authentication, parental authorization, media-operation safeguards, or Cloud tenant isolation. The best fit is an optional **Private Direct** mode, not a forced replacement for Kaevo Cloud Relay.

The local Kaevo candidate now has standards-based household authorization and sender-constrained device/connector sessions, but it does **not** have Tailscale's deployment maturity, independent review, network key lifecycle, posture ecosystem, or operational track record. Kaevo must not be described as universally safer or Tailscale-comparable until staged deployment and independent testing succeed.

Tailscale's data plane uses WireGuard for end-to-end encryption, including DERP-relayed paths; DERP does not receive plaintext. Its control plane distributes identity, keys, and policy while filtering is enforced on devices. See [Tailscale encryption](https://tailscale.com/kb/1504/encryption) and [control/data planes](https://tailscale.com/docs/concepts/control-data-planes).

## Comparison

| Property | Current Kaevo Cloud/Relay | Tailscale private direct | Security conclusion |
|---|---|---|---|
| Internet exposure | Public API and relay; home connector is outbound-only. | Home service is reachable only by permitted tailnet devices. | Tailscale reduces public relay/API data-plane exposure. |
| Transport crypto | HTTPS plus signed, connector-bound grants and an encrypted relay tunnel. | Device-to-device WireGuard; DERP carries encrypted packets. | Both can be strong; Tailscale has a mature network-identity layer. |
| User/device identity | **Partially meets:** Cognito roles, recent auth, installation P-256 keys and DPoP are implemented locally, not deployed. | **Meets:** identity-provider login, node keys, device lifecycle; optional posture. | Tailscale remains stronger operationally for device admission. |
| Least privilege | Application route/operation/grant constraints. | Grants/ACLs restrict devices, users, ports, and resources. | Use both. Network access alone must not imply media/admin authority. |
| Metadata visibility | Kaevo Cloud stores profile/session/request metadata and encrypted/private payload objects. | Coordination service sees device/control metadata, not media plaintext. | Tailscale can minimize Kaevo-held relay metadata. |
| Revocation | **Partially meets:** device/connector revoke and refresh-family reuse revocation pass local tests; deployment drill pending. | **Meets:** remove/expire a node/user or change grants. | Tailscale lifecycle is more mature and independently exercised. |
| Consumer UX | No VPN setup; works through Kaevo account/connector. | Every viewing device must join/authenticate to a tailnet. | Kaevo is simpler for families and guests. |
| tvOS/App Store fit | Normal HTTPS app networking. | Requires Tailscale installed/configured or deeper Network Extension/product integration. | Tailscale increases onboarding/support complexity. |
| Provider credentials | Stay at home; Kaevo connector makes scoped calls. | Stay at home, but an overly broad tailnet rule could expose provider ports. | Keep provider ports inaccessible; expose only a hardened Kaevo gateway. |
| Misconfiguration risk | Capability/route mistakes in Kaevo code. | Tailnet policy mistakes; default policy must be reviewed. | Tailscale docs note policy behavior and recommend grants; Kaevo should ship a deny-by-default template. |

## Recommended design

1. Add `Remote Access Mode`: **Kaevo Relay (default)**, **Private Direct (Tailscale)**, and **Local Only**.
2. In Private Direct, expose only the Kaevo Home gateway over the tailnet—not Jellyfin, Sonarr, Radarr, download clients, Docker, or TrueNAS administration.
3. Provide a generated Tailscale grants policy that permits the household device tag to the Kaevo gateway port only. Tailscale recommends grants for new policies and documents deny-by-default semantics once policy is defined: [access-control grants/ACLs](https://tailscale.com/docs/features/access-control/acls).
4. Require Kaevo app authentication and scoped commands even inside the tailnet. Treat network membership as one signal, not authorization.
5. Support key expiry/revocation and display tailnet device identity in Kaevo's device list.
6. For higher-assurance households, optionally require device posture before gateway access; Tailscale describes posture as continuous/context-aware admission control: [device posture](https://tailscale.com/docs/features/device-posture).
7. Do not route optimizer filesystem mounts, Docker sockets, TrueNAS admin, or provider dashboards through a broad subnet route.

## When Tailscale is better

- Jefferson's own household and technically comfortable private deployments.
- Homes that prioritize minimal public exposure over zero-setup onboarding.
- Administrative access to Kaevo Home Server where no public Cloud command should be permitted.

## When Kaevo Relay remains necessary

- App Store consumers who will not install/manage a VPN.
- Guest or family devices that cannot join a private tailnet cleanly.
- Push/actionable workflows and account sync that require a public control plane.

## Decision

Do not discard the current outbound connector/relay. Harden it for consumer use, then add Tailscale as an opt-in high-security transport. This preserves Kaevo's UX while giving advanced users a smaller network attack surface.

## Tailscale-level reassessment

| Property | Kaevo candidate | Evidence / limit |
|---|---|---|
| Cryptographic device identity | **Meets locally** | P-256 installation keys, Secure Enclave where available, RFC 9449 DPoP tests. No attestation yet. |
| Short-lived sender-constrained sessions | **Meets locally** | 15-minute access tokens, rotating refresh families, wrong-key/replay/reuse tests. |
| Authoritative role and tenant policy | **Meets locally** | Cognito authorizer, principal records, explicit capability matrix, opaque cross-household denial. |
| Connector isolation | **Partially meets** | Unique local keys, atomic pairing, household binding, revoke tests; plugin certificate lifecycle and staged recovery remain. |
| Network-plane least privilege | **Does not meet** | Kaevo is an application relay, not a mature WireGuard overlay/grants engine. |
| Device posture/attestation | **Does not meet** | Risk checks and Apple attestation are not implemented. |
| Operational maturity/independent assurance | **Unable to verify** | No staged production exercise or external penetration test was performed. |
