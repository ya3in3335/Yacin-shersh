# STRYKER X — KNOWN_LIMITATIONS

Honest status as of Phase A. Nothing here is hidden behind a polished UI.

## Not yet implemented (planned by phase)
- **Website Scanner (Phase B)** — FUNCTIONAL (merged from VulnScan): TLS, security headers,
  exposed files, fingerprint; scope/authorization gate; Room persistence; report + AI share.
  Still pending: opt-in active tests (reflected-input/XSS, error-based SQLi) on approved
  targets; CORS deep-dive; true pause/resume (pause currently aborts gracefully).
- **APK Analyzer (Phase C)** — FUNCTIONAL: import an APK via the Storage Access
  Framework; it is copied to cache under a 200 MB cap and never executed. The
  binary manifest is read by the platform `PackageManager` (the authoritative
  parser) for package/version/SDK, permissions and exported components; DEX files
  get a bounded (25 MB) string scan for risky API/secret indicators. Findings are
  persisted and scored like web findings.
  Caveats: uses `PackageManager` rather than a hand-written AXML parser; the DEX
  pass is a bounded string scan, NOT full decompilation; intent-filter-implied
  exports rely on the platform's computed `exported` flag; certificate-chain
  parsing is not done yet.
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

## Deliberate design decisions
- **No runtime download/execution of third-party tools.** The app never fetches
  and runs external binaries/scripts (e.g. sqlmap) on the device: that is a
  supply-chain risk, violates app-store policy, and such tools' full modes
  perform data extraction / DB takeover (destructive). SQLi detection is
  implemented natively instead (error-based across many DBMS + boolean-based
  blind differential), detection-only, opt-in, scope-locked. No time-based
  (sleep) payloads are sent, to avoid loading the target.

## Web scanner caveats
- The TLS protocol/cert probe opens a direct socket with the platform default trust manager;
  it reports negotiated protocol and expiry, not a full cipher-suite audit.
- `SafeHttp` blocks private/reserved/metadata addresses via a custom DNS and re-validates
  redirect hops; it is not a substitute for a network egress firewall.
- Only non-destructive, passive/configuration checks run today. No active injection payloads
  are sent (those are deferred and will be strictly opt-in and scope-locked).

## Safety posture
- Authorization-first by design: a URL is not permission. Scans require an explicit
  authorization declaration, are locked to the target/allow-listed hosts, and are
  rate-limited by the resource profile. No exploitation, credential attacks, destructive
  payloads, or mass scanning.
- A finding is never marked **Confirmed** without reproducible evidence.
