# Kaevo 0.3.46

Kaevo 0.3.46 adds a bounded diagnostic capture for slow hardware-transcoded playback startup. It records local playlist/segment timing, when Jellyfin's encoder job and progress become observable, and when the requested and following segment files exist. This separates encoder startup and segment production from relay delivery.

Capture is off until the administrator uses the existing five-minute playback timing control. It is limited to the selected command and exact playback session, samples for at most the existing 30-second origin window, and stops when the initial segment is available or the operation is cancelled. It reads only existing job state and file existence; it does not change the encoder, source files, quality, playback authorization, or Firebase capacity. Logs contain stage timing and hashed correlation identifiers, not credentials or source paths.

The existing Firebase connector, local hardware scheduling, native player, resume handling and app detail layout are preserved. This release measures the remaining delay; it does not claim the 2–4 second startup target is fixed. Regular Kaevo build 208 remains the current app build.

Validation: 609 plugin tests passed. The exact package passed isolated Jellyfin 10.11.11 startup, Active status, controller and authentication checks, including exercising the new observer against the real server assemblies. These are local/isolated checks, not physical startup acceptance of this plugin on your server.

Install through the existing Kaevo repository in Jellyfin Dashboard → Plugins → Catalog. Choose Kaevo 0.3.46.0, install the update, and restart Jellyfin. Confirm 0.3.46.0 is Active. Keep the existing pairing and repository URL; do not uninstall Kaevo or create a new pairing for this update.

The encoder observations use a 100 ms sampling interval and Jellyfin's own progress reporting cadence. They mark when a state was observed, not the exact first decoded frame or GPU initialization boundary. File existence is never treated as permission to serve incomplete media.
