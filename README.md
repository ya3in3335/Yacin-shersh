# Yacin-shersh — VulnScan

An **authorization-first** vulnerability scanning toolkit:

- **`vulnscan/`** — a Python web vulnerability scanner (CLI).
- **`android/`** — an Android app (Kotlin + Compose) that automates the same
  checks from a phone.
- **`.claude/skills/vuln-scan/`** — a Claude Code skill so that saying
  "افحص لي كذا" / "scan <target>" runs the scanner automatically.

> ⚠️ **For authorized security testing only.** Only scan systems you own or
> have explicit written permission to test. Unauthorized scanning may be
> illegal. Both the CLI and the app require you to confirm authorization, and
> each scan is locked to the single target host.

## Checks
`headers` · `tls` · `exposure` (exposed `.git`/`.env`/backups, directory
listing) · `fingerprint` (CMS/framework + risky HTTP methods) · `injection`
(low-impact reflective XSS / error-based SQLi on existing parameters) ·
`ports` (light common-port TCP connect scan).

## Quick start (CLI)
```bash
pip install -r requirements.txt
python -m vulnscan.cli "https://example.com/app?id=1" --yes --format markdown
```

Run specific checks:
```bash
python -m vulnscan.cli example.com --checks headers,tls,exposure --yes
```

## Android app
See [`android/README.md`](android/README.md). Pushing to the repo triggers a
GitHub Actions workflow that builds an installable APK as a downloadable
artifact.

## Design notes
- Requests are rate-limited and scope-locked to the target host.
- Exposed-file checks require a content signature to avoid false positives
  from SPA catch-all `200`s.
- A failing individual check never aborts the overall scan.
