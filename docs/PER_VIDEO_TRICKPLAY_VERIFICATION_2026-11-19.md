# Per-video trickplay candidate 0.3.92

Status: implemented, isolated-server verified and published with explicit approval; personal-server installation and live acceptance remain pending.

## Behavior

An elevated Jellyfin caller can request generation for one exact local video and server. The existing manager-authorized Cloud metadata command uses the same endpoint. Item-detail responses can carry bounded status for the same authorized item. No library-wide scheduled task or library/encoding setting is changed.

The generator uses Jellyfin's encoder and native tile/metadata storage. It supports readable video files, DVD folders, Blu-ray folders, and unencrypted readable disc images, with duration/frame/pixel limits and one active job per server. Original media is read only. Existing previews remain available during extraction; incomplete output is not reported as success. Completion requires generated tile and native metadata readback. No permanent converted media is produced.

## Evidence

- Plugin suite: 1,051 passed, zero failed.
- Packaged 0.3.92.0 includes the verified dependency bundle (24 files).
- ZIP SHA-256: `35e04ef07828288329c2b0273156a67287f74071ffff3ab9be161a13266642ec`.
- Isolated Jellyfin 10.11.11: final package generated DVD, Blu-ray folder and ISO previews; first/last native JPEG endpoints returned HTTP 200 with JPEG bytes.
- Isolated Jellyfin 12.1.0: DVD, Blu-ray folder, ISO and MP4 generated real previews. Final packaged candidate was installed and Blu-ray generation repeated successfully.
- Duplicate active submissions reused the job. No authorization returned 401; a disposable non-admin user received 403 for generation and status; wrong server returned 409.
- SHA-256 comparisons confirmed all original synthetic disc media unchanged.
- Forced read-only output failure on disposable 10.11.11: job failed, original manifest and every prior tile hash remained unchanged after restoring the temporary library option.
- iOS candidate build 635: 38 focused tests passed; device build succeeded and code signature verified. Old-plugin generic refresh receipts cannot claim a thumbnail job started.

Raw local evidence: `/tmp/kaevo-trickplay-20261119` (test logs, integration JSON, failure-preservation result, app xcresult). Candidate ZIP: `artifacts/trickplay-0.3.92/package/Kaevo.Plugin.KaevoForJellyfin.zip`.

## Remaining gates

Live Cloud command delivery and the iPhone UI have not yet been verified with this new generator. Personal Alvin ISO generation, scrub-preview display, and unchanged playback must be confirmed after the owner's manual plugin installation/restart. Do not close the combined Sentry report or claim TestFlight/public release from isolated evidence. Encrypted/unreadable discs and unsupported native encoder inputs remain explicit generation failures.

Job status is process-local; restart loses the status record. Existing generated native thumbnails persist. This candidate does not add a persistent generation queue.

## Approved publication readback

Published on November 19, 2026 (America/Los_Angeles) as [v0.3.92](https://github.com/karakisin/kaevo-jellyfin-plugin/releases/tag/v0.3.92). Public download and canonical raw catalog were read back successfully. All 171 earlier catalog entries were preserved.

Before publication, stale 0.3.91 release notes and timestamp were corrected in `meta.json`. Every one of the other 23 ZIP members is byte-for-byte identical to the isolated-tested package above. Final public ZIP SHA-256: `c0515517e93dc485a4c46300159fef273bac490c9ada3e4806e28982bf0ed768`; Jellyfin catalog MD5: `b646faef0fd1b6482562de561a83b7a8`.

Release source commit: `aa5adf2`; catalog commit: `869fa27678f514e0f59dba9cd0c7268df5b3fee8`. Public ZIP contains 24 verified files and version 0.3.92.0. Publication does not establish personal installation, app-control availability, or Alvin/Cloud/Mirroring acceptance. No personal server restart or TestFlight submission was performed.
