"""Detection of commonly-exposed sensitive files and misconfigurations."""

from __future__ import annotations

from ..utils import Finding, ScanContext

CHECK = "exposure"

# path -> (severity, title, signature substrings that confirm a real hit)
SENSITIVE_PATHS = {
    "/.git/HEAD": ("high", "Exposed .git repository", ["ref:", "refs/heads"]),
    # Note: no bare "=" signature — it matches any HTML and caused SPA false positives.
    "/.env": ("high", "Exposed .env file", ["APP_", "DB_", "SECRET=", "KEY=", "_TOKEN="]),
    "/.svn/entries": ("medium", "Exposed .svn metadata", ["svn:", "dir\n", "/!svn/"]),
    "/config.php.bak": ("high", "Exposed backup of config.php", ["<?php", "password", "db"]),
    "/wp-config.php.bak": ("high", "Exposed WordPress config backup", ["DB_PASSWORD", "DB_USER"]),
    "/.DS_Store": ("low", "Exposed .DS_Store", ["Bud1", "\x00"]),
    "/phpinfo.php": ("medium", "Exposed phpinfo()", ["PHP Version", "phpinfo"]),
    "/server-status": ("medium", "Exposed Apache server-status", ["Apache Server Status"]),
    "/.htaccess": ("low", "Readable .htaccess", ["RewriteEngine", "Order ", "Deny"]),
    "/backup.zip": ("medium", "Exposed backup archive", ["PK\x03\x04"]),
    "/robots.txt": ("info", "robots.txt present", ["Disallow", "User-agent"]),
}


def _signature(resp):
    """A response fingerprint used to recognize an SPA catch-all page."""
    return (resp.status_code, len(resp.text), resp.text[:512])


def _looks_like_catch_all(baseline, candidate) -> bool:
    """True when candidate is indistinguishable from a 200 catch-all baseline."""
    if baseline is None:
        return False
    b_code, b_len, b_prefix = baseline
    c_code, c_len, c_prefix = candidate
    return b_code == 200 and c_code == 200 and c_len == b_len and c_prefix == b_prefix


def run(ctx: ScanContext) -> None:
    # Establish a catch-all baseline from a random, non-existent path. If the
    # server answers it with 200, it serves the same page for everything (SPA
    # fallback) and a 200 on a probed path proves nothing.
    import time

    baseline = None
    probe = ctx.request("GET", ctx.base_url + f"/vulnscan-404-probe-{int(time.time()*1000)}")
    if probe is not None:
        baseline = _signature(probe)

    for path, (sev, title, signatures) in SENSITIVE_PATHS.items():
        url = ctx.base_url + path
        resp = ctx.request("GET", url)
        if resp is None or resp.status_code != 200:
            continue
        # Skip responses indistinguishable from the SPA catch-all page.
        if _looks_like_catch_all(baseline, _signature(resp)):
            continue
        body = resp.text[:4096]
        # Require a content signature so we don't flag SPA catch-all 200s.
        if signatures and not any(sig in body for sig in signatures):
            continue
        evidence = ""
        if path == "/robots.txt":
            evidence = body[:300]
        ctx.add(
            Finding(
                CHECK,
                title,
                sev,
                url,
                evidence=evidence,
                remediation="Remove the file from the web root or block access to it.",
            )
        )

    # Directory listing detection on the root
    resp = ctx.request("GET", ctx.base_url + "/")
    if resp is not None and resp.status_code == 200:
        if "Index of /" in resp.text and "<title>Index of" in resp.text:
            ctx.add(
                Finding(
                    CHECK,
                    "Directory listing enabled",
                    "medium",
                    ctx.base_url + "/",
                    remediation="Disable autoindex / directory browsing on the web server.",
                )
            )
