# Kaevo Travel Downloads Foundation Pack

Generated: 2026-07-08

This pack prepares the **Travel Downloads** feature before Codex starts touching the app code.

## Core product idea

Travel Downloads lets users download movies and shows for offline watching from their own home server. Kaevo Cloud coordinates preferences and job metadata only. Kaevo Cloud must not host, store, stream, or transcode user media.

## Main pieces in this pack

- `01_PRODUCT_SPEC.md` — build-ready feature spec.
- `02_UX_COPY_AND_FLOWS.md` — user-facing copy for onboarding, settings, last setup, issue handling, and errors.
- `03_SETTINGS_SCHEMA.json` — profile/cloud settings shape.
- `04_KAEVO_CLOUD_API_CONTRACT.md` — backend API contract for preferences and job metadata.
- `05_LOCAL_BRIDGE_CONTRACT.md` — future home-server bridge contract for inspecting, preparing, previewing, and serving offline files.
- `06_SWIFT_MODELS_AND_LOGIC.swift` — app-side models, enums, option-generation logic, storage estimates, and Kaevo Assist action policy.
- `07_SWIFT_TESTS.swift` — XCTest-style tests Codex can adapt.
- `08_RETRY_AND_SAFETY_POLICY.md` — strict safe automation rules for Kaevo Assist.
- `09_PHASED_IMPLEMENTATION_CHECKLIST.md` — safe build order.
- `10_CODEX_PROMPT.md` — ready-to-paste Codex prompt.

## Recommended first Codex pass

Build only the app-side and settings foundation first:

1. Travel Downloads settings model.
2. Settings UI under `Settings > Downloads > Travel Downloads`.
3. Dynamic quality option logic.
4. Use Last Setup flow.
5. Placeholder estimates.
6. Kaevo Assist preference settings.
7. Job/status models only.

Do **not** implement real FFmpeg, Jellyfin download extraction, or transcoding in the first pass.

## Non-negotiable architecture rule

```text
Kaevo Cloud does not host media.
Kaevo Cloud does not transcode media.
Kaevo Cloud only stores settings, preferences, job metadata, status, and user-approved automation rules.

Actual media work happens on the user's home server through Jellyfin or a future Kaevo Local Bridge.
```
