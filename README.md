# KAEVO Workspace

## Welcome

KAEVO is a premium native media platform built around a shared engineering philosophy and a multi-platform architecture.

This repository contains the engineering workspace for KAEVO.

The project currently includes:

- tvOS
- iOS
- Shared engineering documentation
- AI engineering workspace

For product philosophy and engineering principles, read:

`AI/KAEVO_CHARTER.md`

---

## Repository Structure

```
StageDoorNative/          # Root workspace repository
├── AI/                   # Engineering documentation
├── Documentation/        # Project documentation
├── Shared/               # Future shared Swift package
├── tvOS/                 # Native Apple TV application
└── iOS/                  # Native iPhone/iPad application
```

---

## Read Before Working

1. `AI/KAEVO_CHARTER.md`          # Product vision and engineering principles
2. `AI/OPENCODE_ENGINEER.md`       # Engineering workflow and milestones
3. `AI/CURRENT_TASK.md`            # Current active work
4. `AI/AI_MEMORY.md`               # Engineering memory and decisions
5. `PROJECT_INDEX.md`              # Architecture overview
6. `Foundation/`                    # Core architectural patterns

---

## Engineering Workflow

```
Repository Inspection → Planning → Approval → Implementation → Validation → Documentation → Verification
```

Every milestone follows this flow. Work does not advance until all steps are complete and documented.

---

## Current Status

| Item | Value |
|------|-------|
| **Current Milestone** | `M0 — Repository Foundation` |
| **Status** | In Progress |

---

## Roadmap (High Level)

| Milestone | Objective |
|-----------|-----------|
| M0 | Repository Foundation |
| M1 | Foundation (Core, Brand, DesignSystem, Configuration) |
| M2 | Networking (API layer) |
| M3 | Data Models |
| M4 | Services |
| M5 | Navigation |
| M6 | Home Screen |
| M7 | Search |
| M8 | Media Details |
| M9 | Playback |
| M10 | Settings |
| M11 | Downloads |
| M12 | Diagnostics |
| M13 | Polish & Optimization |

### Future Platforms (Roadmap)

- **Apple TV** (tvOS) — Active
- **iPhone / iPad** (iOS) — Planning
- **macOS** — Planned
- **visionOS** — Planned
- **Apple Watch** — Planned

---

## Repository Rules

1. Never modify `tvOS/` unless explicitly instructed.
2. Build iOS using tvOS as reference.
3. Preserve architecture. Intentional changes require an ADR.
4. Keep all documentation synchronized.
5. Validate before completing work.
6. Leave the project better than you found it.

---

## Engineering Documentation

| Document | Purpose |
|----------|---------|
| `AI/KAEVO_CHARTER.md` | Constitution — vision, principles, non-negotiables |
| `AI/OPENCODE_ENGINEER.md` | Engineering contract and workflow |
| `AI/AI_MEMORY.md` | Persistent engineering memory |
| `AI/CURRENT_TASK.md` | Active milestone status |
| `AI/CHANGELOG_AI.md` | Milestone change log |
| `AI/DECISIONS.md` | Decision records |
| `AI/KNOWN_ISSUES.md` | Known issues and known limitations |
| `AI/SESSION_LOG.md` | Session logs |

---

## Architecture Bible Location

> The full tvOS architecture is documented in: `tvOS/tvOS StageDoor/ARCHITECTURE_BIBLE.md`

This repository contains engineering governance only. Platform-specific implementation details live within each platform directory.

## Licensing

KAEVO proprietary. All rights reserved.
