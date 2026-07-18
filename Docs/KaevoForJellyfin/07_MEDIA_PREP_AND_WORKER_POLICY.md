# Media Prep and Worker Policy

## Product Goal

Keep the user experience simple:

Install Kaevo for Jellyfin. Enable features. Done.

But keep Jellyfin stable.

## Phase 1 Policy

Phase 1 is read-only.

Allowed:
- Read Jellyfin users
- Read Jellyfin libraries
- Read metadata
- Read media source info
- Produce compatibility hints
- Store scan summaries
- Report status

Not allowed:
- FFmpeg conversion
- MKV to MP4 remux
- File deletion
- File move
- File rename
- Media download
- Media streaming
- Transcoding
- Writing into media folders

## Future Worker Modes

Built-In Lightweight Mode:
- Status checks
- Metadata scans
- Provider health
- Job orchestration
- Scan summaries

Managed Worker Mode:
- FFmpeg remux
- Offline download package prep
- Audio fallback generation
- Temporary file creation
- Heavy media jobs

## User Experience Rule

Even if a sidecar worker exists later, the user should not feel like they are installing a separate product.

The plugin should guide setup with a button like:

Enable Local Media Prep
