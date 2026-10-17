"""Security-header and cookie hygiene checks."""

from __future__ import annotations

from ..utils import Finding, ScanContext

CHECK = "headers"

# header -> (severity, human title, remediation)
EXPECTED = {
    "strict-transport-security": (
        "medium",
        "Missing HSTS header",
        "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
    ),
    "content-security-policy": (
        "medium",
        "Missing Content-Security-Policy",
        "Define a restrictive CSP to mitigate XSS and data injection.",
    ),
    "x-content-type-options": (
        "low",
        "Missing X-Content-Type-Options",
        "Add 'X-Content-Type-Options: nosniff'.",
    ),
    "x-frame-options": (
        "low",
        "Missing X-Frame-Options / frame-ancestors",
        "Add 'X-Frame-Options: DENY' or a CSP 'frame-ancestors' directive.",
    ),
    "referrer-policy": (
        "info",
        "Missing Referrer-Policy",
        "Add 'Referrer-Policy: strict-origin-when-cross-origin'.",
    ),
}

# headers that leak implementation details
LEAKY = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]


def run(ctx: ScanContext) -> None:
    resp = ctx.request("GET", ctx.base_url)
    if resp is None:
        return
    headers = {k.lower(): v for k, v in resp.headers.items()}

    # CSP also satisfies frame-ancestors expectation
    for name, (sev, title, fix) in EXPECTED.items():
        if name == "x-frame-options" and "content-security-policy" in headers:
            if "frame-ancestors" in headers["content-security-policy"].lower():
                continue
        if name not in headers:
            ctx.add(Finding(CHECK, title, sev, ctx.base_url, remediation=fix))

    for name in LEAKY:
        if name in headers:
            ctx.add(
                Finding(
                    CHECK,
                    f"Information disclosure via '{name}' header",
                    "low",
                    ctx.base_url,
                    evidence=f"{name}: {headers[name]}",
                    remediation=f"Remove or obfuscate the '{name}' response header.",
                )
            )

    # Cookie flags
    for cookie in resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw, "headers") else resp.headers.get("Set-Cookie", "").split("\n"):
        if not cookie:
            continue
        low = cookie.lower()
        name = cookie.split("=", 1)[0].strip()
        missing = [f for f in ("secure", "httponly") if f not in low]
        if "samesite" not in low:
            missing.append("samesite")
        if missing:
            ctx.add(
                Finding(
                    CHECK,
                    f"Cookie '{name}' missing flags: {', '.join(missing)}",
                    "low",
                    ctx.base_url,
                    evidence=cookie[:120],
                    remediation="Set Secure, HttpOnly and SameSite attributes on session cookies.",
                )
            )
