"""Technology / version fingerprinting and risky HTTP method detection."""

from __future__ import annotations

import re

from ..utils import Finding, ScanContext

CHECK = "fingerprint"

TECH_SIGNATURES = [
    ("WordPress", re.compile(r'/wp-(content|includes)/', re.I)),
    ("Drupal", re.compile(r'Drupal\.settings|/sites/default/files', re.I)),
    ("Joomla", re.compile(r'/media/jui/|Joomla!', re.I)),
    ("Laravel", re.compile(r'laravel_session|XSRF-TOKEN', re.I)),
    ("Django", re.compile(r'csrftoken|__admin__', re.I)),
    ("React", re.compile(r'react(\.production|\.development)?\.min\.js|data-reactroot', re.I)),
    ("jQuery", re.compile(r'jquery[-.]?(\d+\.\d+\.\d+)?', re.I)),
]

RISKY_METHODS = {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}


def run(ctx: ScanContext) -> None:
    resp = ctx.request("GET", ctx.base_url)
    if resp is None:
        return

    body = resp.text[:200000]
    headers = {k.lower(): v for k, v in resp.headers.items()}

    detected = []
    for name, pattern in TECH_SIGNATURES:
        if pattern.search(body) or any(pattern.search(v) for v in headers.values()):
            detected.append(name)

    gen = re.search(r'<meta name=["\']generator["\'] content=["\']([^"\']+)', body, re.I)
    if gen:
        detected.append(gen.group(1).strip())

    for tech in headers.get("x-powered-by", "").split(","):
        tech = tech.strip()
        if tech:
            detected.append(tech)

    if detected:
        ctx.add(
            Finding(
                CHECK,
                "Technology stack fingerprinted",
                "info",
                ctx.base_url,
                evidence=", ".join(sorted(set(detected))),
                remediation="Review whether version/stack disclosure is necessary.",
            )
        )

    # Risky HTTP methods via OPTIONS
    opt = ctx.request("OPTIONS", ctx.base_url)
    if opt is not None:
        allow = opt.headers.get("Allow", "") + " " + opt.headers.get("Access-Control-Allow-Methods", "")
        enabled = {m.strip().upper() for m in re.split(r"[,\s]+", allow) if m.strip()}
        risky = sorted(enabled & RISKY_METHODS)
        if risky:
            ctx.add(
                Finding(
                    CHECK,
                    f"Potentially dangerous HTTP methods enabled: {', '.join(risky)}",
                    "medium",
                    ctx.base_url,
                    evidence=f"Allow: {allow.strip()}",
                    remediation="Disable unused HTTP methods (TRACE, PUT, DELETE) at the server/proxy.",
                )
            )
