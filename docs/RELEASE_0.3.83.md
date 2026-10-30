# Kaevo plugin 0.3.83

Adds playback for ISO disc images when Jellyfin negotiates a supported HLS stream. The original ISO stays intact; playback uses temporary streaming segments and does not create a permanent MKV. Native and compatibility players use the existing authorized streaming route.

Includes the previously tested Jellyfin 12 authorization-header compatibility and bounded resume-preroll fixes retained in the candidate. Account/profile/item checks, bitrate limits, selected tracks, design and playback settings are preserved.

Validation: all 924 plugin tests passed, including 30 new ISO cases. Homestead playback and seeking were verified in Jellyfin; playback through the updated Kaevo plugin on a physical device remains pending. Package dependencies are verified.

Unsupported/unreadable disc images remain unsupported. ISO playback with a manual audio-sync offset remains blocked; the offset is not silently discarded. Disc menus and DRM decryption are not added.

Update through the existing Jellyfin plugin catalog, restart Jellyfin, and confirm version 0.3.83.0 before testing Homestead in Kaevo.
