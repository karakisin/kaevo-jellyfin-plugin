# Kaevo 0.3.79

Fresh installations can issue signed V3 QR codes for the Firebase pairing flow. Completion requires the signed-in Jellyfin user to match the verified Kaevo pairing authorization. Interrupted pairing can recover the same connector without creating a duplicate, and installed/configured/connected remain separate states.

Use Kaevo iOS build 519 or later for fresh Firebase pairing. Update the plugin, restart Jellyfin, and generate a fresh code. Existing administrator-configured or paired connectors retain their settings. Playback configuration is unchanged.

Validation: 811 plugin tests passed; dependency-complete packaging verified. End-to-end pairing on the physical phone is pending installation and a fresh scan. Do not treat publication as proof that your server is paired.
