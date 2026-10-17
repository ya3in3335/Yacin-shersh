# VulnScan — Android

An Android front-end that automates the `vulnscan` checks from your phone:
security headers, TLS posture, exposed sensitive files, technology
fingerprinting, and a light common-port scan. Results are grouped by severity.

> **Authorized testing only.** Scan systems you own or have explicit written
> permission to test. The app requires you to tick an authorization checkbox
> before each scan, and every scan is locked to the single host you entered.

## Stack
- Kotlin + Jetpack Compose (Material 3)
- OkHttp for HTTP probing, Kotlin coroutines for concurrency
- `minSdk 24`, `targetSdk 34`

## Build

### Option A — GitHub Actions (no local setup)
Push to the repo; the **Build Android APK** workflow compiles the app and
uploads `vulnscan-debug-apk` as a workflow artifact. Download it, then install
the APK on your device (enable "install unknown apps").

### Option B — Android Studio
Open the `android/` folder in Android Studio (Giraffe or newer) and run.

### Option C — command line
```bash
cd android
gradle assembleDebug          # or ./gradlew assembleDebug if you add the wrapper
# APK: app/build/outputs/apk/debug/app-debug.apk
```

## Checks
| id | what it looks for |
|----|-------------------|
| `headers` | missing HSTS/CSP/X-CTO/X-Frame-Options, info-leak headers, weak cookie flags |
| `tls` | HTTP-only service, weak TLS protocol, expired/soon-expiring certificate |
| `exposure` | exposed `.git`, `.env`, backups, `phpinfo`, `server-status`, directory listing |
| `fingerprint` | CMS/framework detection, risky HTTP methods (PUT/DELETE/TRACE) |
| `ports` | TCP connect scan of common ports; flags sensitive exposed services |
