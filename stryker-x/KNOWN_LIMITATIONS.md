# STRYKER X — KNOWN_LIMITATIONS

Honest status as of Phase A. Nothing here is hidden behind a polished UI.

## Not yet implemented (planned by phase)
- **Website Scanner (Phase B)** — screen is a placeholder; no scanning yet.
- **APK Analyzer (Phase C)** — no APK import/parsing yet.
- **API Inspector + Network Inspector (Phase D)** — placeholders only.
- **Reports (Phase E)** — no PDF/HTML/JSON/Markdown/HackerOne export yet.
- **Scan Orchestrator / WorkManager jobs** — not wired until Phase B.

## Testing limitations
- Phase A tests are pure-JVM only (resource profiles, pause policy, severity reduction,
  enum parsing). Room/instrumented tests (migrations, DAO behavior) are deferred to the
  phase that first needs them; `evaluatePause` is pure precisely so it is testable now.
- No real-device battery/thermal measurements have been taken. `ResourceMonitor` maps the
  Android thermal/battery APIs but hardware behavior is not yet validated on a device.

## Platform caveats
- Memory budgets in `ResourceProfile` are best-effort targets, not OS guarantees.
- `PowerManager.getCurrentThermalStatus()` fidelity varies by device/OEM.
- APK/network features (Phase C/D) will be bounded by Android scoped-storage and network
  permission restrictions.

## Safety posture
- Authorization-first by design: active tests (Phase B+) will be opt-in, scope-locked, and
  rate-limited. No exploitation, credential attacks, destructive payloads, or mass scanning.
- A finding is never marked **Confirmed** without reproducible evidence.
