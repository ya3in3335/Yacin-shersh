---
name: vuln-scan
description: Run the repo's authorization-first web vulnerability scanner against a target the user is authorized to test. Use when the user says "scan <target>", "فحص", "افحص لي كذا", or asks to check a site/host for common web security issues (headers, TLS, exposed files, fingerprinting, open ports).
---

# vuln-scan

Automates the `vulnscan` Python package in this repo to scan a target for
common web security issues and report findings by severity.

## Authorization gate (do this first)
This tool is for **authorized testing only**. Before scanning, confirm the
user owns the target or has explicit written permission to test it. If that is
not already clear from the conversation, ask once and wait. Do not scan hosts
the user has not clearly claimed authority over, and never scan broad ranges or
third-party infrastructure.

## How to run
1. Ensure dependencies: `pip install -r requirements.txt` (just `requests`).
2. Run the scanner, passing `--yes` only after authorization is confirmed:
   ```bash
   python -m vulnscan.cli "<target>" --yes --format markdown
   ```
   - `<target>` is a URL or host, e.g. `https://example.com/app?id=1`.
   - To run specific checks: `--checks headers,tls,exposure`.
     Available: `headers, tls, exposure, fingerprint, injection, ports`.
   - `--format` is one of `text | markdown | json`.
   - `--output report.md` writes to a file instead of stdout.
3. Summarize the findings for the user, highest severity first, and include
   the suggested remediation for each.

## Injection checks
The `injection` check only probes query parameters already present in the URL,
using benign markers / a single quote. Include parameters in the target URL
(e.g. `...?id=1`) if the user wants SQLi/XSS probing.

## Notes
- Every request is rate-limited and locked to the target host (no scope creep).
- A failing individual check never aborts the whole scan.
- There is also an Android app under `android/` that runs the same checks from
  a phone; see `android/README.md`.
