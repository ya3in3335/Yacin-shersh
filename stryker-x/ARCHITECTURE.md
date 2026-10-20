# STRYKER X — ARCHITECTURE

## Overview
Single Gradle module (`:app`) organized by Clean Architecture packages. UI (Compose)
is kept separate from domain and data. Dependency wiring is a manual container
(`di/AppContainer`) to avoid framework overhead in early phases; it can be swapped for
Hilt later without touching feature code.

## Layers / packages (`com.strykerx.lab`)
- `core/common` — enums (`Severity`, `Confidence`, `VerificationStatus`, `ScanState`),
  `SeverityStats` (pure reducer), `StrykerRepository`, `SettingsStore`.
- `core/database` — Room entities, DAOs, `StrykerDatabase`.
- `core/resources` — `ResourceProfile`, `DeviceStatus`/`ThermalLevel`, `evaluatePause`
  policy, `ResourceMonitor` (Android battery/thermal/storage sampling).
- `core/ui` — theme (dark palette) and shared Compose components.
- `navigation` — `Destination` enum + `StrykerNavHost` (bottom nav + NavHost).
- `feature/*` — one package per screen; each exposes a `@Composable` and (where stateful)
  a `ViewModel`. ViewModels receive dependencies via `StrykerViewModelFactory`.
- `di` — `AppContainer`, `StrykerViewModelFactory`.

## Data flow
Room DAOs expose `Flow`s → `StrykerRepository` → ViewModel `combine`/`stateIn` →
`StateFlow<UiState>` → Compose collects with `collectAsStateWithLifecycle`.

## Resource safety
`ResourceMonitor` samples on demand (no continuous polling / wake locks). `evaluatePause`
is a pure function so it is deterministically unit-tested. Scan loops (Phase B+) consult it
between units of work and honor `ResourceProfile` pacing and concurrency.

## Persistence & migrations
Room `version = 1`, `exportSchema = false` for Phase A. Future versions add `Migration`
objects in `StrykerDatabase` (no destructive fallback in release builds). Secrets/tokens/
cookies are never persisted; they are redacted before storage or export.

## Build & CI
Gradle Kotlin DSL; KSP for Room. CI (`.github/workflows/stryker-x.yml`) runs unit tests,
Android lint, then `:app:assembleDebug`, and uploads the APK + reports as artifacts.
