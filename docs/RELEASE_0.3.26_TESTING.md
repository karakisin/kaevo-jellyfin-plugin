# Kaevo 0.3.26 — manual testing release

This package is ready for manual installation testing on Jellyfin 10.11. It is not a completed AWS-to-Firebase migration release. Installing it preserves the existing configuration and AWS connection; Firebase remains gated until connector authentication transfer and activation are separately verified.

Includes the normal Firebase control supervisor, Firestore control listener, signed demand admission, bounded three-channel relay ownership, cancellation and recovery handling, and required managed dependencies. No new pairing is required for an existing installation.

Validation: 480 plugin tests, 3 dependency packaging checks, 44 connected checks using the exact packaged DLL, and an isolated network-disabled Jellyfin 10.11.11 plugin-load and controller smoke test. These are automated checks, not decoded video playback on an iPhone. The reported Home connection failure remains unresolved; this release does not claim to fix it.

## Manual installation

1. In Jellyfin Dashboard → Plugins → Repositories, add `Kaevo Testing` with URL `https://raw.githubusercontent.com/karakisin/kaevo-jellyfin-plugin/release/0.3.26-testing/manifest-testing.json`.
2. Open the plugin Catalog, select Kaevo, choose version 0.3.26.0, and install it. Keep your existing Kaevo configuration and pairing.
3. If Jellyfin requests a restart, perform that restart yourself when ready.
4. Confirm Dashboard → Plugins shows Kaevo 0.3.26.0 active. Open regular Kaevo on the iPhone 14 Pro Max and report what Home shows.

Expected installation result: plugin 0.3.26.0 active with the existing pairing retained. Firebase activation and successful Home/playback are separate pending checks.

The stable catalog and latest stable release remain unchanged. This testing catalog was based on the current remote catalog, preserving all prior entries.

SHA256: `afe5346004f86d99e7b220512cee9de8718d0b2af7009145a2bd7c3de0ed7db6`
