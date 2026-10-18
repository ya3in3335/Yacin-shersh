# STRYKER X — PROJECT_STATE

**Current phase:** Phase A (Foundation) — awaiting approval before Phase B.

## Completed work (Phase A)
- Android project `stryker-x/` initialized (Gradle Kotlin DSL, single `:app` module,
  packaged by Clean Architecture layers). Existing `android/` (VulnScan) untouched.
- Compose + Material 3 dark cybersecurity design system (navy / cyan / emerald).
- Bottom navigation with 5 primary tabs + 3 secondary screens (API Inspector, Reports, Settings).
- **Dashboard**: live counts (completed/active scans, potential/confirmed findings),
  severity distribution, device resource status, recent activity, Quick Start action.
  All values come from the Room DB — no fabricated numbers.
- **Settings**: resource-profile selection (ECO/BALANCED/ADVANCED), delete history.
- **Resource Protection Engine**: `ResourceProfile` (workers/connections/pacing/battery
  thresholds), `ResourceMonitor` (on-demand battery/thermal/storage sampling, no polling),
  `evaluatePause` policy (thermal > storage > battery; charging bypasses battery only).
- **Room DB**: targets, scopes, scan_sessions, findings, error_logs + DAOs + repository.
- Manual DI container (`AppContainer`) + ViewModel factory.
- GitHub Actions workflow `stryker-x.yml` (unit tests → lint → assembleDebug → upload APK).
- Unit tests: resource-profile enforcement, pause policy, severity reduction, enum parsing.
- Placeholder screens for Phase B–E modules (honest "scheduled for Phase X", no fake results).

## Files changed
- `stryker-x/**` (new), `.github/workflows/stryker-x.yml` (new), `.gitignore` (updated).

## Test results
- Local JVM unit tests: see CI (`:app:testDebugUnitTest`).

## Build status
- Verified by GitHub Actions `Build STRYKER X` on push. Not claimed successful until the run is green.

## Blockers
- None known.

## Next action
- On approval: **Phase B — Website Scanner** (URL input, authorization workflow, scope
  validator with DNS-rebinding/redirect-escape protection, HTTP engine, TLS + security
  headers + cookie + CORS checks, findings persistence, tests).
