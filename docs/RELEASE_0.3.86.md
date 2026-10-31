# Plugin 0.3.86

When a rejected Jellyfin key is successfully repaired, existing playback connections now use the same verified and saved replacement as library requests. Previously they could retain the rejected key and return HTTP 401 even while browsing worked.

The replacement stays limited to the original in-memory connector session, server address and configured Jellyfin user. Explicit keys remain authoritative. Recovery still requires the existing plugin-owned key, exact paired server verification and an atomic save; it never creates a replacement for a revoked key. Playback signatures, profiles, media selection, quality and bitrate settings are unchanged.

On October 31, 2026, Jefferson relayed the affected tester’s confirmation that playback now works on their phone. Sentry issue [APPLE-IOS-2V](https://kaevo.sentry.io/issues/7821351609/) ("Can’t connect through cloud") was marked Resolved, preserving its event history. This closes the reported incident; the phone outcome is tester-reported, not a new directly observed device test.

Validation: all 990 plugin tests passed with test collections run sequentially. The packaged DLLs also passed four real-Jellyfin relay checks covering the HLS playlist and media segments at different playback positions. Changed server, connector, user, session and explicit-key cases remain covered. The source fix is commit `f3dfed1983fc58d6799f94266b6f8f88abd28b85`; catalog publication is commit `c301a1c`. No additional runtime changes were needed for closure.
