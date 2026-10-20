"""Scanner check modules. Each exposes run(ctx) -> None and appends Findings."""

from . import exposure, fingerprint, headers, injection, ports, tls

ALL_CHECKS = {
    "headers": headers,
    "tls": tls,
    "exposure": exposure,
    "fingerprint": fingerprint,
    "injection": injection,
    "ports": ports,
}
