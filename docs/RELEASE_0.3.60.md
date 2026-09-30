# Kaevo 0.3.60

Playback preparation now resolves the media source through the authenticated user item lookup and supplies that source to Jellyfin track negotiation. An unselected subtitle is explicitly off instead of inheriting the Jellyfin default, which could force unnecessary subtitle-driven video conversion even though Kaevo displayed no subtitles. Explicit subtitle selections are preserved; mismatched returned sources fail closed.

Regression coverage uses Jellyfin StreamBuilder with the affected H.264/AAC MP4 and default external SRT configuration: inherited subtitles require conversion, while subtitles off permit compatible playback. This release does not certify the two-second startup target; installation and physical iPhone validation remain required. Audio-sync work remains paused.

Validation: 740 .NET tests passed; the dependency-complete package built successfully and loaded as Kaevo 0.3.60.0 in an isolated, network-disabled Jellyfin 10.11.11 instance. No live Jellyfin files or service state were changed.
