"""Command-line entry point for vulnscan."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .checks import ALL_CHECKS
from .report import RENDERERS
from .utils import ScanContext, host_of, normalize_url

BANNER = r"""
  _ __ _   _ _ _  ___ __ __ _ _ _
 | '_ \ || | ' \(_-</ _/ _` | ' \
 | .__/\_,_|_||_/__/\__\__,_|_||_|  vulnscan {ver}
 |_|   authorized security testing only
""".format(ver=__version__)

AUTH_NOTICE = (
    "LEGAL NOTICE: Only scan systems you own or are explicitly authorized "
    "to test. Unauthorized scanning may violate law and policy."
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vulnscan",
        description="Authorization-first web vulnerability scanner.",
        epilog=AUTH_NOTICE,
    )
    p.add_argument("target", help="Target URL or host (e.g. https://example.com/app?id=1)")
    p.add_argument(
        "--checks",
        default="all",
        help="Comma-separated checks to run: " + ",".join(ALL_CHECKS) + " (default: all)",
    )
    p.add_argument("--format", choices=list(RENDERERS), default="text")
    p.add_argument("--output", help="Write the report to this file instead of stdout")
    p.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout seconds")
    p.add_argument("--delay", type=float, default=0.3, help="Delay between requests seconds")
    p.add_argument("--verify-tls", action="store_true", help="Verify TLS certificates")
    p.add_argument(
        "--yes",
        action="store_true",
        help="Confirm you are authorized to test the target (skips the prompt)",
    )
    p.add_argument("--quiet", action="store_true", help="Suppress the banner")
    return p


def confirm_authorization(target: str, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    sys.stderr.write(AUTH_NOTICE + "\n")
    try:
        answer = input(f"Do you have authorization to scan {target}? [y/N] ").strip().lower()
    except EOFError:
        return False
    return answer in ("y", "yes")


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if not args.verify_tls:
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass

    if not args.quiet:
        sys.stderr.write(BANNER + "\n")

    target = normalize_url(args.target)
    scope = host_of(target)
    if not scope:
        sys.stderr.write("error: could not parse a host from the target.\n")
        return 2

    if not confirm_authorization(target, args.yes):
        sys.stderr.write("Aborted: authorization not confirmed.\n")
        return 3

    if args.checks == "all":
        selected = list(ALL_CHECKS)
    else:
        selected = [c.strip() for c in args.checks.split(",") if c.strip()]
        unknown = [c for c in selected if c not in ALL_CHECKS]
        if unknown:
            sys.stderr.write(f"error: unknown checks: {', '.join(unknown)}\n")
            return 2

    ctx = ScanContext(
        base_url=target,
        scope_host=scope,
        timeout=args.timeout,
        delay=args.delay,
        verify_tls=args.verify_tls,
    )

    for name in selected:
        try:
            ALL_CHECKS[name].run(ctx)
        except Exception as exc:  # a failing check must not abort the scan
            sys.stderr.write(f"warning: check '{name}' failed: {exc}\n")

    report = RENDERERS[args.format](target, ctx.findings)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report)
        sys.stderr.write(f"Report written to {args.output}\n")
    else:
        print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
