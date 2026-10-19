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
  parser) for package/version/SDK, permissions and exported components; ALL DEX
  files get a bounded (64 MB budget) string scan for concrete, CWE-tagged
  vulnerability classes — insecure WebView/JS bridge (escalated to CRITICAL when
  a JS bridge correlates with JavaScript enabled), trust-all TLS / disabled
  hostname verification, weak or misused crypto (ECB/DES/3DES/RC4/MD5/SHA-1,
  hardcoded keys), world-readable/writable storage, SQL-injection surfaces,
  dynamic code loading, command execution, mutable PendingIntents — plus
  high-value hardcoded-secret patterns (AWS/Google/Firebase/Stripe/Twilio/
  SendGrid/GitHub/Slack/JWT/private keys and generic password/api-key literals,
  redacted in output) and a backend attack-surface map (referenced hosts/URLs,
  cleartext endpoints, and cloud backends such as Firebase DBs and public
  buckets flagged for authorized follow-up). Findings are persisted and scored
  like web findings.
  It also fingerprints bundled third-party libraries (OkHttp, Retrofit, Gson,
  Jackson, Bouncy Castle, Commons Collections, Netty, Cordova, SQLCipher, etc.)
  from DEX type descriptors and looks them up ONLINE against the public CVE
  database (OSV.dev — aggregates CVE/GHSA advisories, no API key). Matches are
  reported with the CVE/GHSA ids, advisory summary and severity. This network
  call connects ONLY to the CVE database, never to the analyzed app's servers;
  it fails safe offline (an informational "CVE lookup skipped" note). When a
  library version is embedded and extracted, the match is version-exact
  (CONFIRMED); otherwise it is reported as POTENTIAL with a note to verify the
  bundled version against the affected ranges. Exact versions are extracted
  authoritatively from Gradle's `META-INF/<group>_<artifact>.version` files when
  present, which upgrades many library matches from a version-unknown lead to a
  version-exact CONFIRMED CVE.

- **Full-archive file analysis** — the analyzer unpacks the whole APK and scans
  every packaged file, not just DEX: text resources/assets (.json/.xml/.js/.env/
  .properties/…) for secrets and endpoints (API keys and Firebase configs often
  live in assets, not code), native `.so` libraries (string-scanned for URLs),
  embedded executable payloads (a secondary dex/apk/jar in assets → packer/dropper
  indicator), commercial packers/protectors (by native-lib fingerprint), plus an
  archive inventory. Bounded in memory; fully offline. Caveat: native code is only
  string-scanned, not disassembled; packed apps unpack real code at runtime, so a
  static pass sees little until a dynamic/unpacking step is added.
- **Cherlogons Privacy Radar** — our own, in-house tracker/SDK signature engine
  (`TrackerSignatures`). It fingerprints bundled trackers, ad networks, analytics,
  crash, profiling, push and location SDKs from DEX type descriptors, fully
  offline — no external service is contacted. A match means the SDK is bundled
  (reported CONFIRMED); runtime use is a separate question. This is entirely our
  engine, not a dependency on any third-party privacy database.

### What static analysis proves (and what it does not)
- **Facts (reported CONFIRMED):** manifest flags (debuggable, cleartext,
  allowBackup), exported components without a permission guard, the signing
  certificate, and a known CVE in a library whose exact version was extracted.
  These are verifiable and are the report-worthy findings.
- **Reachable paths (reported CONFIRMED, via dexlib2 data-flow):** for each
  exported component, the analyzer disassembles the bytecode and reports when a
  single method both reads attacker-controllable input (Intent/URI) and reaches a
  dangerous sink (SQL, WebView, command exec, dynamic loading). This proves a
  path from an attacker-reachable entry point to a sink exists — stronger than a
  string match. It is intra-method source+sink co-occurrence, NOT full
  inter-procedural taint, and it does NOT prove end impact (auth bypass, data
  disclosure, financial action): confirming exploitability still requires a
  runtime PoC on an authorized target. The tool says exactly this and no more.
- **Leads (reported POTENTIAL):** DEX string/API matches (WebView, crypto,
  SQLi surfaces) and version-unknown library CVEs. A string match is NOT proof
  of an exploitable vulnerability — it is a lead the owner (or an authorized
  dynamic test) must confirm. The tool deliberately does not claim exploitability
  it cannot demonstrate; proving runtime exploitability requires authorized
  dynamic/instrumented testing, which is out of scope for this static analyzer.
  It can also analyze apps already INSTALLED on the device: the user picks one
  from a searchable list and it is analyzed in place from its on-device APK path
  (no copy, never deleted). Listing installed apps needs the QUERY_ALL_PACKAGES
  permission (fine for a sideloaded auditing tool; Google Play restricts it).
  Some protected apps' base APKs may not be readable; those report a clear error.
  Caveats: uses `PackageManager` rather than a hand-written AXML parser; the DEX
  pass is a bounded string scan, NOT full decompilation — a string match is a
  lead to confirm, not proof, so most DEX findings are reported as POTENTIAL;
  intent-filter-implied exports rely on the platform's computed `exported` flag;
  certificate-chain parsing is not done yet. Cloud/Firebase endpoints are only
  flagged statically — the app never connects to them to confirm exposure.
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
