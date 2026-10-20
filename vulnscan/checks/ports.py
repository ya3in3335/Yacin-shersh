"""Light TCP connect scan of common service ports on the in-scope host.

A connect scan (full TCP handshake) of a small, curated port list on a single
authorized host. Not a mass/stealth scanner by design.
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

from ..utils import Finding, ScanContext

CHECK = "ports"

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
    9200: "Elasticsearch",
    27017: "MongoDB",
}

# Ports that are noteworthy if reachable from the public internet.
RISKY_IF_OPEN = {23: "Telnet", 445: "SMB", 3389: "RDP", 6379: "Redis",
                 9200: "Elasticsearch", 27017: "MongoDB", 5900: "VNC"}


def _probe(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


def run(ctx: ScanContext) -> None:
    host = urlparse(ctx.base_url).hostname or ctx.scope_host
    if host != ctx.scope_host:
        return

    open_ports = {}
    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = {
            port: pool.submit(_probe, host, port, min(ctx.timeout, 3.0))
            for port in COMMON_PORTS
        }
        for port, fut in futures.items():
            if fut.result():
                open_ports[port] = COMMON_PORTS[port]

    if open_ports:
        listing = ", ".join(f"{p}/{svc}" for p, svc in sorted(open_ports.items()))
        ctx.add(
            Finding(
                CHECK,
                "Open TCP ports discovered",
                "info",
                host,
                evidence=listing,
                remediation="Ensure only required services are internet-exposed; firewall the rest.",
            )
        )

    for port, svc in sorted(open_ports.items()):
        if port in RISKY_IF_OPEN:
            ctx.add(
                Finding(
                    CHECK,
                    f"Sensitive service exposed: {svc} (port {port})",
                    "medium",
                    f"{host}:{port}",
                    remediation=f"Restrict {svc} to trusted networks or disable public access.",
                )
            )
