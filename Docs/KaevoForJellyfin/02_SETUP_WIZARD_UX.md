# Setup Wizard UX — Kaevo for Jellyfin

## Setup Entry

After installing the plugin, the Jellyfin dashboard should show:

- Kaevo for Jellyfin
- Setup Status
- Pair With Kaevo
- Connected Services
- Selected Libraries
- Selected Users
- Scan Status

## First Screen

Title:
Kaevo for Jellyfin

Body:
Connect this Jellyfin server to Kaevo so your Apple devices can use your Jellyfin library with Kaevo profiles, smart home rows, travel downloads, and future automation.

Primary button:
Pair With Kaevo

Secondary button:
Configure Manually

## Pairing Flow

The plugin should generate a short-lived pairing code.

Example:
KAEVO-842913

Pairing code rules:
- Short-lived
- One-time use
- Redacted in logs
- Does not reveal provider secrets
- Can be revoked

## Questions During Setup

Step 1: Choose Jellyfin Users

Prompt:
Which Jellyfin users should Kaevo use?

Step 2: Choose Libraries

Prompt:
Which libraries should Kaevo show?

Step 3: Optional Services

Prompt:
Do you use Seerr, Sonarr, or Radarr?

Default:
Skip for now.

Step 4: Advanced Features

Toggles:
- Smart Home Rows
- Travel Downloads Foundation
- Compatibility Scan
- Smart Download Recovery Later

Default:
Only safe/read-only features enabled.

## Setup Complete

Title:
Kaevo is connected.

Buttons:
- Open Status
- Run Compatibility Scan
- Manage Libraries
- Manage Services

## UX Rule

Do not overwhelm the user with technical details unless they expand Advanced Diagnostics.
