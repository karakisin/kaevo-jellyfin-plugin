# Kaevo plugin 0.3.90

Adds the approved owner-only Cloud request-removal command. It validates connector, request, TMDB media ID, media type and quality; performs one DELETE; and reads the request back to confirm absence. Uncertain deletion responses are not retried automatically. Media files, Arr records and downloader jobs are not removed.

Validation before release: 1,027 plugin tests, 47 Cloud emulator tests and 95 app simulator tests passed. Real Seerr 3.4.1 movie/TV removal, read-only retry, identity-mismatch rejection and unrelated request/media preservation passed in an isolated no-network fixture. The companion app and physical acceptance remain separate release gates.
