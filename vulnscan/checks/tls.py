"""TLS / certificate posture checks (passive, connection-based)."""

from __future__ import annotations

import datetime
import socket
import ssl
from urllib.parse import urlparse

from ..utils import Finding, ScanContext

CHECK = "tls"

WEAK_PROTOCOLS = {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}


def run(ctx: ScanContext) -> None:
    parsed = urlparse(ctx.base_url)
    if parsed.scheme != "https":
        ctx.add(
            Finding(
                CHECK,
                "Service not served over HTTPS",
                "medium",
                ctx.base_url,
                remediation="Serve all traffic over TLS and redirect HTTP to HTTPS.",
            )
        )
        return

    host = parsed.hostname or ""
    port = parsed.port or 443
    if host != ctx.scope_host:
        return

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=ctx.timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                version = ssock.version()
    except (OSError, ssl.SSLError) as exc:
        ctx.add(
            Finding(CHECK, "TLS handshake failed", "info", ctx.base_url, detail=str(exc))
        )
        return

    if version in WEAK_PROTOCOLS:
        ctx.add(
            Finding(
                CHECK,
                f"Weak TLS protocol negotiated: {version}",
                "high",
                ctx.base_url,
                remediation="Disable TLS 1.1 and older; require TLS 1.2+.",
            )
        )

    # Certificate validity against a trusting context (separate probe)
    trust_ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=ctx.timeout) as sock:
            with trust_ctx.wrap_socket(sock, server_hostname=host):
                pass
    except ssl.SSLCertVerificationError as exc:
        ctx.add(
            Finding(
                CHECK,
                "Certificate failed validation",
                "high",
                ctx.base_url,
                evidence=str(exc),
                remediation="Install a valid certificate chain trusted by major roots.",
            )
        )
    except (OSError, ssl.SSLError):
        pass

    if cert and "notAfter" in cert:
        try:
            expires = datetime.datetime.strptime(
                cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
            )
            days = (expires - datetime.datetime.utcnow()).days
            if days < 0:
                ctx.add(
                    Finding(
                        CHECK,
                        "TLS certificate expired",
                        "high",
                        ctx.base_url,
                        evidence=f"notAfter={cert['notAfter']}",
                        remediation="Renew the certificate immediately.",
                    )
                )
            elif days < 15:
                ctx.add(
                    Finding(
                        CHECK,
                        f"TLS certificate expires soon ({days} days)",
                        "low",
                        ctx.base_url,
                        evidence=f"notAfter={cert['notAfter']}",
                        remediation="Renew the certificate before expiry.",
                    )
                )
        except ValueError:
            pass
