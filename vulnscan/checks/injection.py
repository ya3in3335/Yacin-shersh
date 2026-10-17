"""Low-impact reflective XSS and error-based SQL injection probing.

Only parameters already present in the target URL are tested. Payloads are
benign unique markers / a single quote — no destructive input is ever sent.
This mirrors the low-intensity passive detection of mainstream scanners.
"""

from __future__ import annotations

import re
import time
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..utils import Finding, ScanContext

CHECK = "injection"

# Signatures of database errors reflected into a response.
SQL_ERRORS = [
    re.compile(r"SQL syntax.*MySQL", re.I),
    re.compile(r"Warning.*\Wmysqli?_", re.I),
    re.compile(r"PostgreSQL.*ERROR", re.I),
    re.compile(r"unterminated quoted string", re.I),
    re.compile(r"ORA-\d{5}", re.I),
    re.compile(r"Microsoft OLE DB Provider for SQL Server", re.I),
    re.compile(r"SQLite/JDBCDriver|SQLite3::", re.I),
    re.compile(r"Unclosed quotation mark after the character string", re.I),
]

XSS_MARKER = "vsx9z7q"  # unique, harmless token
XSS_PAYLOAD = f"'\"><{XSS_MARKER}>"


def _build(url: str, params: list, key: str, value: str) -> str:
    new = [(k, value if k == key else v) for k, v in params]
    parsed = urlparse(url)
    return urlunparse(parsed._replace(query=urlencode(new)))


def run(ctx: ScanContext) -> None:
    parsed = urlparse(ctx.base_url)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    if not params:
        # Nothing to test without parameters; note it for the operator.
        ctx.add(
            Finding(
                CHECK,
                "No query parameters to test for injection",
                "info",
                ctx.base_url,
                detail="Provide a URL with parameters (e.g. ?id=1) to enable injection probing.",
            )
        )
        return

    for key, _ in params:
        # --- Error-based SQLi: a single quote ---
        sqli_url = _build(ctx.base_url, params, key, "1'")
        resp = ctx.request("GET", sqli_url)
        if resp is not None:
            for pat in SQL_ERRORS:
                if pat.search(resp.text):
                    ctx.add(
                        Finding(
                            CHECK,
                            f"Possible SQL injection in parameter '{key}'",
                            "high",
                            sqli_url,
                            evidence=pat.pattern,
                            remediation="Use parameterized queries / prepared statements.",
                        )
                    )
                    break

        # --- Reflective XSS: unique marker ---
        xss_url = _build(ctx.base_url, params, key, XSS_PAYLOAD)
        resp = ctx.request("GET", xss_url)
        if resp is not None and f"<{XSS_MARKER}>" in resp.text:
            ctx.add(
                Finding(
                    CHECK,
                    f"Reflected input without encoding in parameter '{key}' (possible XSS)",
                    "high",
                    xss_url,
                    evidence=f"Marker <{XSS_MARKER}> reflected unencoded",
                    remediation="Context-aware output encoding; apply a strict CSP.",
                )
            )
