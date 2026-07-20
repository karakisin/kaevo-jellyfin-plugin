# Plugin Branding and Privacy Contract

Updated: 2026-07-20

## Configuration-page presentation

- The header uses the official transparent Kaevo logo mark and wordmark.
- Artwork is embedded in the plugin and served from local read-only branding
  endpoints. The settings page does not load branding from the internet.
- Remote Access, Library, and Media Services cards share the same content width,
  edge alignment, padding, and responsive behavior.
- The QR code, one-time code, and live expiration timer remain centered inside
  their pairing panel.

## Plain-language privacy promise

The settings page communicates three stable promises:

1. **Private at home.** Passwords, API keys, local addresses, and media remain
   on the Jellyfin server.
2. **Connected with purpose.** Kaevo Cloud coordinates authenticated sign-in,
   device pairing, connector status, and user-approved Kaevo actions through the
   plugin.
3. **Nothing extra.** Kaevo Cloud does not receive Jellyfin passwords, provider
   credentials, media files, or unrestricted home-network access.

This copy intentionally describes the product boundary without publishing
implementation details that would turn the settings page into security
documentation.

## Pairing behavior

- Pairing begins only from an elevated Jellyfin administrator session.
- The QR code and human-readable code represent the same ticket.
- Each ticket expires after ten minutes and can be consumed only once.
- Expiration is shown with a live countdown; expired content is visibly disabled.
