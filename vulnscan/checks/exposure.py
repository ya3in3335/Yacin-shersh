"""Detection of commonly-exposed sensitive files and misconfigurations."""

from __future__ import annotations

from ..utils import Finding, ScanContext

CHECK = "exposure"

# path -> (severity, title, signature substrings that confirm a real hit)
SENSITIVE_PATHS = {
    "/.git/HEAD": ("high", "Exposed .git repository", ["ref:", "refs/heads"]),
    "/.env": ("high", "Exposed .env file", ["=", "APP_", "DB_", "SECRET", "KEY"]),
    "/.svn/entries": ("medium", "Exposed .svn metadata", ["svn", "dir"]),
    "/config.php.bak": ("high", "Exposed backup of config.php", ["<?php", "password", "db"]),
    "/wp-config.php.bak": ("high", "Exposed WordPress config backup", ["DB_PASSWORD", "DB_USER"]),
    "/.DS_Store": ("low", "Exposed .DS_Store", ["Bud1", "\x00"]),
    "/phpinfo.php": ("medium", "Exposed phpinfo()", ["PHP Version", "phpinfo"]),
    "/server-status": ("medium", "Exposed Apache server-status", ["Apache Server Status"]),
    "/.htaccess": ("low", "Readable .htaccess", ["RewriteEngine", "Order ", "Deny"]),
    "/backup.zip": ("medium", "Exposed backup archive", ["PK\x03\x04"]),
    "/robots.txt": ("info", "robots.txt present", ["Disallow", "User-agent"]),
}


def run(ctx: ScanContext) -> None:
    for path, (sev, title, signatures) in SENSITIVE_PATHS.items():
        url = ctx.base_url + path
        resp = ctx.request("GET", url)
        if resp is None or resp.status_code != 200:
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
