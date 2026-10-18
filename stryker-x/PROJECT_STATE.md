# Cherlogons (formerly STRYKER X) — PROJECT_STATE

## Rebrand + power + i18n update
- Renamed app to **Cherlogons** (detective theme); new adaptive launcher icon
  (magnifier + check) and in-app logo. Package namespace unchanged.
- New powerful web checks (all non-destructive, authorized): CORS misconfig,
  extended security headers (COOP/CORP/XPCDP, CSP quality, legacy XSS auditor),
  passive recon (DNS A/AAAA, mixed content, secret/token pattern exposure),
  much larger exposed-file wordlist (git/svn/hg, .env variants, actuator,
  swagger/openapi, SQL dumps, backups, docker-compose, etc.), and an OPT-IN
  injection check (reflected XSS + error-based SQLi on URL params, scope-gated).
- Added a **Settings language center**: 7 in-app languages (EN/AR/FR/ES/DE/TR/RU)
  switchable live, with RTL layout for Arabic. UI chrome localized via an in-app
  translation table (technical finding text stays English by design).

---

# STRYKER X — PROJECT_STATE

**Current phase:** Phase A ✅ (CI green) + Phase B integration (Website Scanner now functional).

## Integration update (merge of VulnScan engine into STRYKER X)
The proven VulnScan scanning engine was merged into the STRYKER X architecture, making
the Website Scanner real instead of a placeholder:
- `core/network/SafeHttp`: scope-enforcing OkHttp client — custom DNS rejects private/
  reserved addresses (DNS-rebinding defense at connect time), manual redirect handling
  re-validates each hop (no scope expansion), bounded response body, timeouts.
- `scanner/web`: `ScopeValidator`/`ScopePolicy` (authorization gate, allowlist, SSRF guard)
  + ported checks (TLS, security headers, exposed files, fingerprint) producing `WebFinding`.
- `scanner/orchestrator/WebScanOrchestrator`: scope verify → checks → dedup → persist to
  Room, honoring resource-profile pacing + pause policy, cancellable via Stop Scan.
- `feature/webscanner`: real URL input, authorization + internal-network toggles, START/STOP,
  progress, live findings; `feature/findings`: live DB-backed list.
- `feature/reports`: `ReportBuilder` (Markdown, HackerOne, AI prompt) + `ReportSharer`
  (share text / export .md / send to on-device AI app).
- Findings keep honest verification status (missing headers = Potential/Info, reachable
  sensitive file = Confirmed; never Confirmed without reproducible evidence).

**Phase A status:** CI run succeeded (foundation builds + unit tests + lint green).

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
- Verify the merge build is green in CI, then await direction for **Phase C (APK Analyzer)**.
- Remaining for a fuller Phase B: opt-in active checks (reflected-input/XSS, error-based
  SQLi) restricted to approved targets; CORS deep-dive; pause/resume (currently pause aborts
  gracefully with a recorded reason).
