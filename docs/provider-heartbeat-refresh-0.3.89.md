# Provider configuration refresh 0.3.89

Saving provider enablement previously updated request processing but left heartbeat availability tied to startup configuration. The heartbeat now reads the saved provider projection on each cycle, only when connector token and playback grant key still match its session. A missing, corrupt, cancelled or changed pairing cannot advertise stale provider availability. Transport credentials and playback behavior are unchanged.

Validation: all 1006 plugin tests passed. The isolated App Review server loaded 0.3.89. Saving enabled Radarr/Seerr was reflected in the Cloud heartbeat at 2026-11-09T00:41:29Z; disabling them was reflected at 00:50:32Z, without a server restart between saves. Personal server installation is separate. App Search recovery is tested and released independently.
