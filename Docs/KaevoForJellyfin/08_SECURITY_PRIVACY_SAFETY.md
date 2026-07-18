# Security, Privacy, and Safety

## Core Rule

Kaevo Cloud must not host, store, stream, transcode, or download user media.

## Apple App Secret Rule

iOS/tvOS must not store third-party provider secrets directly.

No Apple app storage for:
- Seerr API key
- Sonarr API key
- Radarr API key
- TMDb API key
- Jellyfin admin token

## Plugin Secret Rule

The plugin/server side may store provider secrets only if needed and must protect them as much as the platform allows.

Secrets must be:
- Redacted in logs
- Redacted in API responses
- Redacted in diagnostics exports
- Never returned to Apple clients after save

## Pairing Rules

Pairing codes:
- Expire quickly
- Are one-time use
- Are redacted in logs
- Can be regenerated
- Can be revoked

## API Safety

Phase 1 API is read-only except:
- setup save
- pairing start/complete
- provider test/save

No destructive endpoints in Phase 1.
