"""Shared helpers: HTTP session, rate limiting, findings, scope control."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import requests

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

DEFAULT_UA = "vulnscan/1.0 (+authorized-security-testing)"


@dataclass
class Finding:
    """A single scanner result."""

    check: str
    title: str
    severity: str  # info | low | medium | high | critical
    target: str
    detail: str = ""
    evidence: str = ""
    remediation: str = ""

    def as_dict(self) -> dict:
        return {
            "check": self.check,
            "title": self.title,
            "severity": self.severity,
            "target": self.target,
            "detail": self.detail,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


@dataclass
class ScanContext:
    """Holds configuration + the in-scope host for a single scan run."""

    base_url: str
    scope_host: str
    timeout: float = 10.0
    delay: float = 0.3  # politeness delay between requests (seconds)
    verify_tls: bool = False
    max_retries: int = 1
    user_agent: str = DEFAULT_UA
    findings: list = field(default_factory=list)

    _session: Optional[requests.Session] = None
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _last_request: float = 0.0

    @property
    def session(self) -> requests.Session:
        if self._session is None:
            s = requests.Session()
            s.headers.update({"User-Agent": self.user_agent})
            s.max_redirects = 5
            self._session = s
        return self._session

    def in_scope(self, url: str) -> bool:
        """Only allow requests to the host we were authorized to scan."""
        host = urlparse(url).hostname or ""
        return host == self.scope_host

    def request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """Rate-limited, scope-enforced HTTP request. Returns None on error."""
        if not self.in_scope(url):
            return None
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", self.verify_tls)
        kwargs.setdefault("allow_redirects", True)

        with self._lock:
            wait = self.delay - (time.monotonic() - self._last_request)
            if wait > 0:
                time.sleep(wait)
            self._last_request = time.monotonic()

        last_err: Optional[Exception] = None
        for _ in range(self.max_retries + 1):
            try:
                return self.session.request(method, url, **kwargs)
            except requests.RequestException as exc:
                last_err = exc
        return None

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)


def normalize_url(raw: str) -> str:
    """Ensure a scheme is present; default to https."""
    raw = raw.strip()
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    return raw.rstrip("/")


def host_of(url: str) -> str:
    return urlparse(url).hostname or ""
