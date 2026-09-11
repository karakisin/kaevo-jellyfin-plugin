# Firebase connector request signatures

Version0.3.42 uses signature version3 for signed connector requests to the exact Firebase gateway selected by the existing endpoint policy. The retained connector ID, key pair, plugin instance, Jellyfin server and profile bindings do not change.

The wire transcript remains Pairing V3 `connector-request`, in this order:

1. `httpMethod`
2. `canonicalRoute`
3. `bodyDigest` (SHA256 of the exact transmitted JSON bytes, base64url)
4. `timestamp`
5. `nonce`
6. `connectorId`
7. `pluginInstanceId`
8. `pluginKeyId`
9. `pluginPublicKeyFingerprint`
10. `targetProject` (`project-d2d72828-62c4-48d1-8ca`)
11. `targetOrigin` (`https://kaevo-development-mobile-9z2mf5rz.wl.gateway.dev`)

The request header is `X-Kaevo-Plugin-Signature-Version: 3`. There is no retry with an older signature if Firebase rejects it. Existing legacy backend requests retain their existing transcript; Firebase-selected operation does not fall back to AWS. A Firebase signature cannot verify as a legacy AWS signature, even if its version header is rewritten.

The matching Firebase backend must accept version3 before this plugin is installed. The backend can then verify a fresh installed-plugin heartbeat and finalize the existing connector's Firebase assignment. Finalization is an independently verified operator action; installing this package does not fabricate a transfer receipt, delete AWS data, or establish full migration completion. After finalization, Firebase refuses legacy connector signatures while retaining revocation, replay protection, profile binding and relay readiness checks.

Install as a normal update through the existing Jellyfin catalog and restart Jellyfin manually. Keep the existing configuration and pairing. No iPhone sign-out, re-pairing QR, or profile recreation is required for this update. This release does not change the native player, video detail page, codec selection, playback timing or idle budgets.
