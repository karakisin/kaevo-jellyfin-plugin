# iOS tvOS Reference Map

Use the tvOS project as a reference only. Do not move or rewrite tvOS files for iOS work.

## Direct Concept References

- `API/StageDoorAPI.swift`: async actor transport style, typed endpoint methods, no URLSession outside API.
- `API/StageDoorAPIError.swift`: LocalizedError surface for view models.
- `Brand/*`: Kaevo identity, primitives, spacing, type, icons, and motion vocabulary.
- `DesignSystem/*`: semantic bridge over Brand tokens.
- `Configuration/BackendConfiguration.swift`: single owner for backend URL state.
- `Models/*`: defensive decoding strategy and backend field terminology.
- `Playback/*`: backend PSE remains playback authority; client resolves returned PlaybackDecision.
- `Features/Settings/*`: provider/settings terminology and connection-state model.

## Adaptation Rules

- iOS navigation uses tabs/stacks, not tvOS sidebar focus behavior.
- iOS controls follow touch conventions, not remote focus scaling.
- Playback client identifier should be `ios`, not `appletv`.
- Shared concepts may be copied into iOS now and extracted to a shared package later.
