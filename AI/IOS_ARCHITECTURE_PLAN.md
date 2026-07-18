# iOS Architecture Plan

## Objective

Build the iOS Kaevo client as a fresh native app while using the tvOS project only as reference material for brand, terminology, architecture, models, API conventions, playback concepts, settings concepts, and documentation style.

## Source Of Truth

- Product brand: Kaevo.
- Backend/internal codename: StageDoor.
- Backend API authority: StageDoor FastAPI backend.
- Playback authority: backend Playback Strategy Engine.
- Client rule: Views render state and forward user intent; they do not own transport, decoding, playback strategy, or settings persistence.

## Layering

1. Features: SwiftUI screens and feature view models.
2. Playback: iOS playback presentation and PSE consumption.
3. Services: focused domain plumbing such as images and resume reporting.
4. API and Configuration: transport and backend URL ownership.
5. Models: defensive Decodable payloads shared conceptually with tvOS.
6. DesignSystem: semantic UI tokens.
7. Brand: primitive identity, color, spacing, type, asset, and motion values.

Dependencies flow down. Feature views may depend on view models, design tokens, and models. Networking remains inside StageDoorAPI.

## Phase 1 Shape

Phase 1 creates a compileable app shell and the source folders that future feature work can grow into. It intentionally avoids copying tvOS UI behaviors that are specific to focus, Top Shelf, or sidebar navigation.
