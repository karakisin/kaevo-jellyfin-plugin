# Kaevo for Jellyfin 0.3.27

Fixes QR repair for older paired configurations that already contain the approved development Cloud URL but have no saved environment field. Explicit configured or process environment restrictions still take precedence; a QR or request URL cannot choose the environment. Existing pairing, server/profile identities, provider configuration and credentials are retained.

Validation: all487 plugin tests pass, including7 new legacy-environment cases. The24-file dependency package is verified. See the published compatibility evidence for the exact packaged Jellyfin10.11.11 isolated load check. These checks do not establish physical QR completion or decoded iPhone playback.

Update through the same Kaevo repository and existing main/manifest.json catalog. In Jellyfin Dashboard → Plugins → Catalog → Kaevo, install0.3.27.0 and restart Jellyfin yourself when prompted. Keep all existing settings and pairing. Then generate a fresh Repair Kaevo Connection QR and scan it using regular Kaevo on the iPhone14ProMax. Expected: the saved Cloud endpoint is accepted and pairing can proceed to the Cloud redemption step.

Firebase activation and the previously reported Home failure remain pending verification. This update does not activate Firebase or complete the migration.
