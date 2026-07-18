# Kaevo for Jellyfin Foundation

This folder documents the first version of Kaevo for Jellyfin.

The product direction is:

One Jellyfin plugin install. One guided setup. No multi-container maze for normal users.

## Core Decision

Build this as a Jellyfin plugin first.

The plugin should handle setup, pairing, user/library selection, status, provider configuration, and read-only scans.

A heavier media worker can exist later, but only as an optional internal/managed advanced path. Normal users should still experience the setup as one Kaevo flow.

## Important Rule

Do not make the Apple app store Jellyfin, Seerr, Sonarr, Radarr, or TMDb secrets directly.

The iOS/tvOS app talks to Kaevo Cloud and/or the Kaevo local plugin endpoint.

The plugin/server side owns provider secrets.
