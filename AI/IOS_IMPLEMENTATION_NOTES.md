# iOS Implementation Notes

## Current State

The iOS project already exists at `iOS/iOS StageDoor`. It started as the default SwiftData template with `ContentView`, `Item`, and a SwiftData model container in the app entry point.

## Phase 1 Implementation Direction

- Remove SwiftData from the entry point until a real persistence need exists.
- Keep `ContentView` as a compatibility wrapper that presents `RootView`.
- Use `@Observable` for mutable app configuration and feature state.
- Keep placeholder screens intentionally thin so future work can replace them without unpicking template code.
- Prefer platform-agnostic source where practical, but do not introduce a shared package in Phase 1.

## Build Notes

The Xcode project uses filesystem-synchronized groups, so source files placed under the app folder should be included by the app target automatically.
