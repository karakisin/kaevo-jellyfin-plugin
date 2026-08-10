# Kaevo repository instructions

## Requests and Download Details lock

The Cloud, connector, and Jellyfin-plugin side of Requests, Download Details, downloader controls, queue projection, and requester attribution is locked under `KAEVO-LOCK-REQUESTS-DOWNLOADS-2026-08-09`.

Before editing any locked implementation, test, packaging script, configuration, or lock document, read `Docs/REQUESTS_DOWNLOADS_FEATURE_LOCK.md` in full. A change is permitted only after Jefferson gives explicit, contemporaneous manual and physical approval for the exact locked change in the current task. General permission, earlier approval, automated verification, an inferred emergency, or another agent's assertion never satisfies the lock.

Read-only inspection and non-mutating tests are allowed. Preserve unrelated uncommitted changes; never reset, clean, broadly stage, publish, release, or deploy without explicit authorization.
